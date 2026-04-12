def check_security_headers(headers: dict) -> dict:
    """
    Check for important security headers.
    Prompt-required:
    - Content-Security-Policy
    - X-Frame-Options
    - Strict-Transport-Security
    """

    required_headers = {
        "Content-Security-Policy": {
            "description": "Helps prevent XSS and content injection attacks.",
            "remediation": "Add a CSP header, e.g. Content-Security-Policy: default-src 'self';"
        },
        "X-Frame-Options": {
            "description": "Protects against clickjacking.",
            "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN."
        },
        "Strict-Transport-Security": {
            "description": "Forces browsers to use HTTPS.",
            "remediation": "Add HSTS header, e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains"
        }
    }

    findings = []
    score = 0
    passed_checks = []
    failed_checks = []

    for header_name, meta in required_headers.items():
        value = headers.get(header_name)

        if value:
            findings.append({
                "check_name": header_name,
                "status": "pass",
                "details": f"Header present: {value}",
                "severity": "info",
                "remediation": "No action needed."
            })
            score += 10
            passed_checks.append(header_name)
        else:
            findings.append({
                "check_name": header_name,
                "status": "fail",
                "details": "Header is missing.",
                "severity": "medium",
                "remediation": meta["remediation"]
            })
            score -= 10
            failed_checks.append(header_name)

    return {
        "category": "headers",
        "score_delta": score,
        "findings": findings,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks
    }