import re
from datetime import datetime
from ipaddress import ip_address


AUTH_TIMESTAMP_RE = (
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)

IP_RE = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"


SSH_FAILED_RE = re.compile(
    AUTH_TIMESTAMP_RE
    + r".*sshd\[\d+\]: Failed password for "
    + r"(?:invalid user )?"
    + r"(?P<username>\S+) from "
    + IP_RE
    + r" port (?P<port>\d+)"
)


SSH_ACCEPTED_RE = re.compile(
    AUTH_TIMESTAMP_RE
    + r".*sshd\[\d+\]: Accepted "
    + r"(?P<auth_method>password|publickey) for "
    + r"(?P<username>\S+) from "
    + IP_RE
    + r" port (?P<port>\d+)"
)


WEB_ACCESS_RE = re.compile(
    r"(?P<ip>\S+)\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>[^"\s]+)"\s+'
    r"(?P<status_code>\d{3})\s+"
    r"(?P<bytes_sent>\S+)"
)


def is_valid_ip(value):
    """
    Checks whether a string is a valid IP address.
    """
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def parse_auth_timestamp(month, day, time_value, year=None):
    """
    Linux auth logs usually do not include the year.

    Example auth timestamp:
        May 25 10:01:11

    This function adds the current year and converts it into ISO format.
    """
    year = year or datetime.now().year
    raw_value = f"{year} {month} {day} {time_value}"
    parsed = datetime.strptime(raw_value, "%Y %b %d %H:%M:%S")
    return parsed.isoformat()


def parse_web_timestamp(timestamp):
    """
    Parses Apache/Nginx-style timestamps.

    Example:
        25/May/2026:10:05:01 +0000
    """
    try:
        parsed = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
        return parsed.isoformat()
    except ValueError:
        return timestamp


def parse_auth_log_line(line):
    """
    Parses one Linux SSH/auth log line.

    Returns a dictionary if the line is useful.
    Returns None if the line is not relevant.
    """
    line = line.rstrip("\n")

    failed_match = SSH_FAILED_RE.search(line)

    if failed_match:
        data = failed_match.groupdict()

        if not is_valid_ip(data["ip"]):
            return None

        return {
            "timestamp": parse_auth_timestamp(
                data["month"],
                data["day"],
                data["time"]
            ),
            "source": "auth.log",
            "event_type": "ssh_failed_login",
            "ip": data["ip"],
            "username": data["username"],
            "method": "password",
            "path": None,
            "status_code": None,
            "raw_log": line,
        }

    accepted_match = SSH_ACCEPTED_RE.search(line)

    if accepted_match:
        data = accepted_match.groupdict()

        if not is_valid_ip(data["ip"]):
            return None

        return {
            "timestamp": parse_auth_timestamp(
                data["month"],
                data["day"],
                data["time"]
            ),
            "source": "auth.log",
            "event_type": "ssh_successful_login",
            "ip": data["ip"],
            "username": data["username"],
            "method": data["auth_method"],
            "path": None,
            "status_code": None,
            "raw_log": line,
        }

    return None


def parse_web_log_line(line):
    """
    Parses one Apache/Nginx-style access log line.

    Returns a dictionary if parsing succeeds.
    Returns None if the line does not match the expected format.
    """
    line = line.rstrip("\n")

    match = WEB_ACCESS_RE.search(line)

    if not match:
        return None

    data = match.groupdict()

    if not is_valid_ip(data["ip"]):
        return None

    return {
        "timestamp": parse_web_timestamp(data["timestamp"]),
        "source": "access.log",
        "event_type": "web_request",
        "ip": data["ip"],
        "username": None,
        "method": data["method"],
        "path": data["path"],
        "status_code": int(data["status_code"]),
        "raw_log": line,
    }


def parse_line(line, log_type):
    """
    Routes a log line to the correct parser.

    log_type should be:
        auth
        web
    """
    log_type = log_type.lower().strip()

    if log_type == "auth":
        return parse_auth_log_line(line)

    if log_type == "web":
        return parse_web_log_line(line)

    raise ValueError(f"Unsupported log_type: {log_type}")
