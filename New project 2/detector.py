import re
from collections import defaultdict


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
USER_PATTERNS = [
    re.compile(r"invalid user\s+['\"]?([A-Za-z0-9._@-]+)", re.IGNORECASE),
    re.compile(r"(?:failed|accepted) password for(?: invalid user)?\s+['\"]?([A-Za-z0-9._@-]+)", re.IGNORECASE),
    re.compile(r"user(?:name)?[=:]\s*['\"]?([A-Za-z0-9._@-]+)", re.IGNORECASE),
    re.compile(r"for\s+['\"]?([A-Za-z0-9._@-]+)\s+from\b", re.IGNORECASE),
]
TIME_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b"),
    re.compile(r"\b\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\b"),
]

FAILED_LOGIN_RE = re.compile(
    r"(failed password|failed login|login failed|authentication failure|invalid user|auth failed|401\s+unauthorized)",
    re.IGNORECASE,
)
SUCCESS_LOGIN_RE = re.compile(
    r"(accepted password|successful login|login successful|session opened|logged in|200\s+login)",
    re.IGNORECASE,
)
SQLI_RE = re.compile(
    r"('|\")?\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
    r"union\s+(all\s+)?select|information_schema|sleep\s*\(|benchmark\s*\(|"
    r"xp_cmdshell|drop\s+table|insert\s+into|--\s|#|/\*.*?\*/",
    re.IGNORECASE,
)
TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e%252f|/etc/passwd|"
    r"boot\.ini|win\.ini|php://filter|file://|/proc/self/environ)",
    re.IGNORECASE,
)


def extract_ip(line):
    match = IP_RE.search(line)
    return match.group(0) if match else "Unknown"


def extract_user(line):
    for pattern in USER_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return "Unknown"


def extract_time_evidence(line):
    for pattern in TIME_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(0)
    return "Not available"


def make_event(event_type, line_number, line, **metadata):
    return {
        "event_type": event_type,
        "line_number": line_number,
        "source_ip": extract_ip(line),
        "username": extract_user(line),
        "time_evidence": extract_time_evidence(line),
        "evidence": line.strip(),
        "metadata": metadata,
    }


def detect_events(lines):
    events = []
    failed_logins_by_ip = defaultdict(list)

    for index, line in enumerate(lines, start=1):
        if FAILED_LOGIN_RE.search(line):
            event = make_event("failed_login", index, line)
            events.append(event)
            failed_logins_by_ip[event["source_ip"]].append(event)

        if SUCCESS_LOGIN_RE.search(line):
            events.append(make_event("successful_login", index, line))

        if SQLI_RE.search(line):
            events.append(make_event("sql_injection", index, line, pattern="SQL injection indicator"))

        if TRAVERSAL_RE.search(line):
            events.append(make_event("directory_traversal_lfi", index, line, pattern="Traversal or local file inclusion indicator"))

    events.extend(detect_brute_force(failed_logins_by_ip))
    return sorted(events, key=lambda item: (item["line_number"], item["event_type"]))


def detect_brute_force(failed_logins_by_ip, threshold=5):
    brute_force_events = []
    for source_ip, failures in failed_logins_by_ip.items():
        if len(failures) < threshold:
            continue

        first_failure = failures[0]
        brute_force_events.append(
            {
                "event_type": "brute_force",
                "line_number": first_failure["line_number"],
                "source_ip": source_ip,
                "username": first_failure.get("username", "Unknown"),
                "time_evidence": first_failure.get("time_evidence", "Not available"),
                "evidence": f"{len(failures)} failed login attempts observed from {source_ip}.",
                "metadata": {
                    "failed_attempts": len(failures),
                    "first_line": failures[0]["line_number"],
                    "last_line": failures[-1]["line_number"],
                    "first_time_evidence": failures[0].get("time_evidence", "Not available"),
                    "last_time_evidence": failures[-1].get("time_evidence", "Not available"),
                    "threshold": threshold,
                },
            }
        )
    return brute_force_events
