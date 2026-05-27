RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def score_findings(findings):
    return [score_finding(finding) for finding in findings]


def score_finding(finding):
    event_type = finding["event_type"]
    metadata = finding.get("metadata", {})

    if event_type == "failed_login":
        score = 20
    elif event_type == "successful_login":
        score = 10
    elif event_type == "brute_force":
        score = min(95, 58 + int(metadata.get("failed_attempts", 0)) * 4)
    elif event_type == "possible_account_compromise":
        score = 98
    elif event_type == "failed_then_success":
        score = min(98, 75 + int(metadata.get("prior_failed_attempts", 0)) * 3)
    elif event_type == "sql_injection":
        score = 82
        evidence = finding.get("evidence", "").lower()
        if any(marker in evidence for marker in ("drop table", "xp_cmdshell", "sleep(", "benchmark(")):
            score = 92
    elif event_type == "directory_traversal_lfi":
        score = 74
        evidence = finding.get("evidence", "").lower()
        if any(marker in evidence for marker in ("/etc/passwd", "boot.ini", "win.ini", "php://filter")):
            score = 88
    else:
        score = 30

    finding["risk_score"] = score
    finding["risk_level"] = risk_level(score)
    return finding


def risk_level(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def highest_risk(findings):
    if not findings:
        return "Low"
    return max((finding["risk_level"] for finding in findings), key=lambda level: RISK_ORDER[level])
