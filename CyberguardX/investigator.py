from collections import defaultdict


EVENT_TITLES = {
    "failed_login": "Failed login attempt",
    "successful_login": "Successful login",
    "brute_force": "Possible brute-force attack",
    "failed_then_success": "Failed logins followed by success",
    "possible_account_compromise": "Possible Account Compromise",
    "sql_injection": "SQL injection indicator",
    "directory_traversal_lfi": "Directory traversal or LFI indicator",
}

TACTICS = {
    "failed_login": "Initial access probing",
    "successful_login": "Authentication activity",
    "brute_force": "Credential attack",
    "failed_then_success": "Possible account compromise",
    "possible_account_compromise": "Possible account compromise",
    "sql_injection": "Web application attack",
    "directory_traversal_lfi": "File disclosure attempt",
}


def investigate(events, lines):
    findings = []
    investigation_agent_events = correlate_account_compromise(events)

    for event in [*events, *investigation_agent_events]:
        findings.append(event_to_finding(event, lines))
    return findings


def correlate_account_compromise(events, minimum_failures=2):
    failures_by_ip = defaultdict(list)
    compromise_events = []

    for event in events:
        if event["event_type"] == "failed_login":
            failures_by_ip[event.get("source_ip", "Unknown")].append(event)

    for success in [event for event in events if event["event_type"] == "successful_login"]:
        source_ip = success.get("source_ip", "Unknown")
        if source_ip == "Unknown":
            continue

        prior_failures = [
            failure
            for failure in failures_by_ip.get(source_ip, [])
            if failure["line_number"] < success["line_number"]
        ]
        if len(prior_failures) < minimum_failures:
            continue

        first_failure = prior_failures[0]
        last_failure = prior_failures[-1]
        username = success.get("username")
        if not username or username == "Unknown":
            username = most_specific_username(prior_failures)

        compromise_events.append(
            {
                "event_type": "possible_account_compromise",
                "line_number": success["line_number"],
                "source_ip": source_ip,
                "username": username,
                "time_evidence": success.get("time_evidence", "Not available"),
                "evidence": (
                    f"{len(prior_failures)} failed login attempts from {source_ip} were followed "
                    f"by a successful login on line {success['line_number']}. "
                    f"Success evidence: {success.get('evidence', '')}"
                ),
                "metadata": {
                    "failed_attempts": len(prior_failures),
                    "success_after_failure": True,
                    "first_failed_line": first_failure["line_number"],
                    "last_failed_line": last_failure["line_number"],
                    "successful_line": success["line_number"],
                    "first_failed_time_evidence": first_failure.get("time_evidence", "Not available"),
                    "last_failed_time_evidence": last_failure.get("time_evidence", "Not available"),
                    "successful_time_evidence": success.get("time_evidence", "Not available"),
                },
            }
        )

    return compromise_events


def most_specific_username(events):
    for event in reversed(events):
        username = event.get("username")
        if username and username != "Unknown":
            return username
    return "Unknown"


def event_to_finding(event, lines):
    context = get_context(lines, event["line_number"])
    return {
        "title": EVENT_TITLES.get(event["event_type"], "Security event"),
        "event_type": event["event_type"],
        "line_number": event["line_number"],
        "source_ip": event.get("source_ip", "Unknown"),
        "username": event.get("username", "Unknown"),
        "time_evidence": event.get("time_evidence", "Not available"),
        "evidence": event.get("evidence", ""),
        "context": context,
        "metadata": event.get("metadata", {}),
        "tactic": TACTICS.get(event["event_type"], "Security monitoring"),
        "investigation_note": build_investigation_note(event),
    }


def get_context(lines, line_number, radius=1):
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    context = []
    for current_line in range(start, end + 1):
        context.append(
            {
                "line_number": current_line,
                "text": lines[current_line - 1].strip(),
            }
        )
    return context


def build_investigation_note(event):
    metadata = event.get("metadata", {})
    event_type = event["event_type"]

    if event_type == "brute_force":
        return (
            f"Correlated {metadata.get('failed_attempts', 0)} failed login events "
            f"between lines {metadata.get('first_line')} and {metadata.get('last_line')}."
        )
    if event_type == "failed_then_success":
        return (
            f"Found {metadata.get('prior_failed_attempts', 0)} failed login attempt(s) "
            f"before a success on line {metadata.get('successful_line')}."
        )
    if event_type == "possible_account_compromise":
        return (
            "Investigation Agent correlated "
            f"{metadata.get('failed_attempts', 0)} failed login attempt(s) from the same source IP "
            f"before a successful login on line {metadata.get('successful_line')}. "
            f"Success after failure: {metadata.get('success_after_failure', False)}."
        )
    if event_type == "sql_injection":
        return "Request content matched SQL injection signatures commonly seen in web access logs."
    if event_type == "directory_traversal_lfi":
        return "Request content referenced path traversal or sensitive local file patterns."
    if event_type == "failed_login":
        return "Authentication failure found and retained for correlation."
    if event_type == "successful_login":
        return "Successful authentication event retained for correlation with earlier failures."
    return "Event retained for analyst review."
