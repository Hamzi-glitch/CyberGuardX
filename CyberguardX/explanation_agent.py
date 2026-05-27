def add_explanations(findings):
    return [add_explanation(finding) for finding in findings]


def add_explanation(finding):
    event_type = finding["event_type"]
    source_ip = finding.get("source_ip", "Unknown")
    line_number = finding.get("line_number", "Unknown")
    metadata = finding.get("metadata", {})

    if event_type == "failed_login":
        explanation = (
            f"A login attempt from {source_ip} failed on line {line_number}. "
            "A single failure can be normal, but repeated failures may indicate password guessing."
        )
        actions = ["Review the account involved.", "Watch for repeated failures from the same source."]
    elif event_type == "successful_login":
        explanation = (
            f"A successful login from {source_ip} was observed on line {line_number}. "
            "This is tracked because it can become suspicious when it follows earlier failures."
        )
        actions = ["Confirm the login is expected.", "Compare the source IP with normal user behavior."]
    elif event_type == "brute_force":
        attempts = metadata.get("failed_attempts", 0)
        explanation = (
            f"{attempts} failed login attempts came from {source_ip}. "
            "That pattern is consistent with a brute-force or password-spraying attempt."
        )
        actions = ["Temporarily block or rate-limit the source IP.", "Review affected accounts.", "Require MFA where possible."]
    elif event_type == "possible_account_compromise":
        attempts = metadata.get("failed_attempts", 0)
        success_time = metadata.get("successful_time_evidence", "Not available")
        explanation = (
            f"The Investigation Agent found {attempts} failed login attempts from {source_ip} "
            f"followed by a successful login. This is labeled Critical because it may indicate "
            f"that repeated authentication failures ended with valid account access. "
            f"Successful login time evidence: {success_time}."
        )
        actions = [
            "Verify the successful login with the account owner.",
            "Review all activity after the successful login.",
            "Reset credentials and require MFA if the login is unauthorized.",
            "Preserve the relevant logs for incident handling.",
        ]
    elif event_type == "failed_then_success":
        attempts = metadata.get("prior_failed_attempts", 0)
        explanation = (
            f"A successful login from {source_ip} occurred after {attempts} failed attempt(s). "
            "This can indicate that an attacker guessed or obtained valid credentials."
        )
        actions = ["Verify the login with the account owner.", "Reset credentials if unauthorized.", "Review session activity after login."]
    elif event_type == "sql_injection":
        explanation = (
            "The log line contains characters or keywords often used in SQL injection attempts. "
            "This suggests someone may have tried to manipulate a database-backed request."
        )
        actions = ["Check whether the request reached application code.", "Confirm parameterized queries are used.", "Review WAF and application logs."]
    elif event_type == "directory_traversal_lfi":
        explanation = (
            "The request includes path traversal or local file inclusion indicators. "
            "This suggests an attempt to read files outside the intended web directory."
        )
        actions = ["Confirm the requested path was not served.", "Review file access controls.", "Normalize and validate user-supplied paths."]
    else:
        explanation = "CyberGuardX found a security-relevant event that should be reviewed by an analyst."
        actions = ["Review the evidence and surrounding log context."]

    finding["summary"] = build_summary(finding)
    finding["explanation"] = explanation
    finding["recommended_actions"] = actions
    return finding


def build_summary(finding):
    return (
        f"{finding['risk_level']} risk: {finding['title']} "
        f"from {finding.get('source_ip', 'Unknown')} on line {finding.get('line_number', 'Unknown')}."
    )
