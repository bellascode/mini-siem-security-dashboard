import argparse
import time
from pathlib import Path

from app.database import (
    init_db,
    insert_event,
    insert_alerts,
    fetch_all_events,
    count_events,
    count_alerts,
)

from app.detector import run_detection
from app.parser import parse_line


DEFAULT_AUTH_LOG = "sample_logs/sample_auth.log"
DEFAULT_WEB_LOG = "sample_logs/sample_access.log"


def open_log_file(path, from_start=False):
    """
    Opens a log file for real-time monitoring.

    By default, the monitor starts at the end of the file.
    That means it only reads new lines added after the monitor starts.

    Use --from-start to read the whole file from the beginning.
    """
    path = Path(path)

    if not path.exists():
        print(f"[WARN] Log file does not exist, skipping: {path}")
        return None

    file_handle = path.open("r", encoding="utf-8", errors="ignore")

    if not from_start:
        file_handle.seek(0, 2)

    return file_handle


def trim_recent_events(recent_events, max_size):
    """
    Keeps only the latest max_size events in memory.

    This prevents the monitor from using unlimited memory.
    """
    if len(recent_events) > max_size:
        del recent_events[0:len(recent_events) - max_size]


def print_event(event):
    """
    Prints one parsed event in a readable format.
    """
    print(
        f"[EVENT] {event['event_type']} | "
        f"IP={event.get('ip')} | "
        f"user={event.get('username')} | "
        f"path={event.get('path')} | "
        f"status={event.get('status_code')}"
    )


def print_new_alert(alert):
    """
    Prints one newly inserted alert.
    """
    print(
        f"[NEW ALERT] [{alert['severity']}] "
        f"{alert['alert_type']} from {alert.get('ip')} "
        f"({alert.get('evidence_count', 0)} related events)"
    )


def main():
    cli = argparse.ArgumentParser(
        description="Real-time Mini SIEM log monitor."
    )

    cli.add_argument(
        "--auth-log",
        default=DEFAULT_AUTH_LOG,
        help="Path to Linux auth log file"
    )

    cli.add_argument(
        "--web-log",
        default=DEFAULT_WEB_LOG,
        help="Path to web access log file"
    )

    cli.add_argument(
        "--from-start",
        action="store_true",
        help="Read existing log contents from the beginning"
    )

    cli.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds to wait between checking for new log lines"
    )

    cli.add_argument(
        "--window",
        type=int,
        default=200,
        help="Number of recent events to keep in memory for detection"
    )

    args = cli.parse_args()

    init_db()

    recent_events = fetch_all_events()[-args.window:]

    print("Mini SIEM real-time monitor started")
    print(f"Loaded {len(recent_events)} existing events into detection window")
    print(f"Current database events: {count_events()}")
    print(f"Current database alerts: {count_alerts()}")
    print()

    targets = [
        {
            "path": Path(args.auth_log),
            "log_type": "auth",
            "handle": open_log_file(args.auth_log, args.from_start),
        },
        {
            "path": Path(args.web_log),
            "log_type": "web",
            "handle": open_log_file(args.web_log, args.from_start),
        },
    ]

    targets = [
        target
        for target in targets
        if target["handle"] is not None
    ]

    if not targets:
        raise SystemExit("No valid log files to monitor.")

    print("Monitoring these files:")

    for target in targets:
        print(f"- {target['path']} as {target['log_type']}")

    print()
    print("Waiting for new log lines...")
    print("Press CTRL+C to stop.")
    print()

    try:
        while True:
            saw_new_line = False

            for target in targets:
                file_handle = target["handle"]

                while True:
                    line = file_handle.readline()

                    if not line:
                        break

                    saw_new_line = True

                    event = parse_line(line, target["log_type"])

                    if not event:
                        print(f"[SKIP] Could not parse line from {target['path']}: {line.strip()}")
                        continue

                    insert_event(event)
                    recent_events.append(event)
                    trim_recent_events(recent_events, args.window)

                    print_event(event)

                    generated_alerts = run_detection(recent_events)
                    inserted_alerts = insert_alerts(generated_alerts)

                    for alert in inserted_alerts:
                        print_new_alert(alert)

            if not saw_new_line:
                time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        print("\nMonitor stopped by user.")

    finally:
        for target in targets:
            target["handle"].close()


if __name__ == "__main__":
    main()