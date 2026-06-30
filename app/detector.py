from collections import defaultdict
from datetime import datetime, timezone


BRUTE_FORCE_THRESHOLD = 4
WEB_SCANNING_THRESHOLD = 3
MULTIPLE_USERNAME_THRESHOLD = 3


SUSPICIOUS_PATHS = {
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/admin",
    "/login",
    "/config",
    "/server-status",
    "/wp-login.php",
    "/backup",
    "/debug",
}


def utc_now():
    """
    Returns the current UTC time in ISO format.
    """
    return datetime.now(timezone.utc).isoformat()


def build_alert(alert_type, severity, ip, description, evidence_count):
    """
    Creates a standard alert dictionary.

    This keeps all alerts in the same format before inserting them
    into the database.
    """
    return {
        "timestamp": utc_now(),
        "alert_type": alert_type,
        "severity": severity,
        "ip": ip,
        "description": description,
        "evidence_count": evidence_count,
    }


def detect_ssh_bruteforce(events, threshold=BRUTE_FORCE_THRESHOLD):
    """
    Detects repeated failed SSH logins from the same IP address.

    Example:
        4 failed SSH logins from 185.220.101.45
    """
    failed_logins_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if event["event_type"] == "ssh_failed_login":
            failed_logins_by_ip[event["ip"]].append(event)

    for ip, failed_events in failed_logins_by_ip.items():
        if len(failed_events) >= threshold:
            usernames = sorted({
                event["username"]
                for event in failed_events
                if event.get("username")
            })

            description = (
                f"{len(failed_events)} failed SSH login attempts detected "
                f"from {ip}. Targeted usernames: {', '.join(usernames)}"
            )

            alerts.append(
                build_alert(
                    alert_type="SSH Brute Force",
                    severity="High",
                    ip=ip,
                    description=description,
                    evidence_count=len(failed_events),
                )
            )

    return alerts


def detect_multiple_usernames_from_one_ip(events, threshold=MULTIPLE_USERNAME_THRESHOLD):
    """
    Detects one IP trying several different usernames.

    This can indicate username enumeration or credential stuffing.
    """
    usernames_by_ip = defaultdict(set)
    alerts = []

    for event in events:
        if event["event_type"] == "ssh_failed_login" and event.get("username"):
            usernames_by_ip[event["ip"]].add(event["username"])

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= threshold:
            sorted_usernames = sorted(usernames)

            description = (
                f"{ip} attempted SSH logins for {len(usernames)} different usernames: "
                f"{', '.join(sorted_usernames)}"
            )

            alerts.append(
                build_alert(
                    alert_type="Multiple Username SSH Attack",
                    severity="High",
                    ip=ip,
                    description=description,
                    evidence_count=len(usernames),
                )
            )

    return alerts


def detect_web_scanning(events, threshold=WEB_SCANNING_THRESHOLD):
    """
    Detects suspicious web requests.

    Suspicious examples:
        /wp-admin
        /phpmyadmin
        /.env
        many 404 responses
    """
    suspicious_requests_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if event["event_type"] != "web_request":
            continue

        path = event.get("path") or ""
        status_code = event.get("status_code")

        suspicious_path = path.lower() in SUSPICIOUS_PATHS
        suspicious_status = status_code in (401, 403, 404)

        if suspicious_path or suspicious_status:
            suspicious_requests_by_ip[event["ip"]].append(event)

    for ip, suspicious_events in suspicious_requests_by_ip.items():
        if len(suspicious_events) >= threshold:
            paths = sorted({
                event["path"]
                for event in suspicious_events
                if event.get("path")
            })

            description = (
                f"{len(suspicious_events)} suspicious web requests detected "
                f"from {ip}. Paths: {', '.join(paths)}"
            )

            alerts.append(
                build_alert(
                    alert_type="Web Scanning",
                    severity="Medium",
                    ip=ip,
                    description=description,
                    evidence_count=len(suspicious_events),
                )
            )

    return alerts


def detect_successful_login_after_failures(events):
    """
    Detects a successful SSH login from an IP that previously failed.

    This is a higher-severity signal because it may indicate that
    a brute-force attempt eventually worked.
    """
    failed_ips = set()
    alerts = []

    for event in events:
        if event["event_type"] == "ssh_failed_login":
            failed_ips.add(event["ip"])

        elif event["event_type"] == "ssh_successful_login":
            ip = event["ip"]

            if ip in failed_ips:
                description = (
                    f"Successful SSH login from {ip} after previous failed login attempts. "
                    f"Username: {event.get('username')}"
                )

                alerts.append(
                    build_alert(
                        alert_type="Successful Login After Failures",
                        severity="Critical",
                        ip=ip,
                        description=description,
                        evidence_count=1,
                    )
                )

    return alerts


def run_detection(events):
    """
    Runs all detection rules and returns a list of alerts.
    """
    alerts = []

    alerts.extend(detect_ssh_bruteforce(events))
    alerts.extend(detect_multiple_usernames_from_one_ip(events))
    alerts.extend(detect_web_scanning(events))
    alerts.extend(detect_successful_login_after_failures(events))

    return alerts