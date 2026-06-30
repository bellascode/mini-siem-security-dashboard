import argparse
from pathlib import Path

from app.database import (
    init_db,
    insert_events,
    insert_alerts,
    reset_db,
    count_events,
    count_alerts,
)

from app.detector import run_detection
from app.parser import parse_line


DEFAULT_AUTH_LOG = "sample_logs/sample_auth.log"
DEFAULT_WEB_LOG = "sample_logs/sample_access.log"


def ingest_file(file_path, log_type):
    """
    Reads a log file, parses each line, and returns parsed events.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    parsed_events = []
    skipped_lines = 0

    with file_path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            event = parse_line(line, log_type)

            if event:
                parsed_events.append(event)
            else:
                skipped_lines += 1

    return parsed_events, skipped_lines


def main():
    cli = argparse.ArgumentParser(
        description="Parse sample logs, store events, and generate SIEM alerts."
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
        "--reset",
        action="store_true",
        help="Delete the existing SQLite database before ingesting"
    )

    args = cli.parse_args()

    if args.reset:
        reset_db()
    else:
        init_db()

    auth_events, auth_skipped = ingest_file(args.auth_log, "auth")
    web_events, web_skipped = ingest_file(args.web_log, "web")

    all_events = auth_events + web_events

    insert_events(all_events)

    generated_alerts = run_detection(all_events)
    inserted_alerts = insert_alerts(generated_alerts)

    print("Mini SIEM ingestion complete")
    print(f"Parsed auth events: {len(auth_events)}")
    print(f"Skipped auth lines: {auth_skipped}")
    print(f"Parsed web events: {len(web_events)}")
    print(f"Skipped web lines: {web_skipped}")
    print(f"Inserted events this run: {len(all_events)}")
    print(f"Generated alert candidates this run: {len(generated_alerts)}")
    print(f"New unique alerts inserted: {len(inserted_alerts)}")
    print(f"Total events in database: {count_events()}")
    print(f"Total alerts in database: {count_alerts()}")

    if inserted_alerts:
        print("\nNew alerts inserted:")

        for alert in inserted_alerts:
            print(
                f"- [{alert['severity']}] "
                f"{alert['alert_type']} "
                f"from {alert['ip']} "
                f"({alert['evidence_count']} related events)"
            )


if __name__ == "__main__":
    main()