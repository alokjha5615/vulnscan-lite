import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_ssl_tls(url: str) -> dict:
    """
    Inspect SSL/TLS certificate and connection details.
    """

    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme

    findings = []
    passed_checks = []
    failed_checks = []
    score = 0

    if scheme != "https":
        findings.append({
            "check_name": "HTTPS Usage",
            "status": "fail",
            "details": "Website is not using HTTPS.",
            "severity": "high",
            "remediation": "Install an SSL/TLS certificate and redirect HTTP traffic to HTTPS."
        })
        failed_checks.append("HTTPS Usage")
        score -= 20

        return {
            "category": "ssl_tls",
            "score_delta": score,
            "findings": findings,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks
        }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                cipher = secure_sock.cipher()

        passed_checks.append("HTTPS Usage")
        findings.append({
            "check_name": "HTTPS Usage",
            "status": "pass",
            "details": "Website is using HTTPS.",
            "severity": "info",
            "remediation": "No action needed."
        })
        score += 10

        not_after = cert.get("notAfter")
        issuer = cert.get("issuer")
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expiry_dt - now).days

        if days_left > 30:
            findings.append({
                "check_name": "Certificate Expiration",
                "status": "pass",
                "details": f"Certificate is valid and expires in {days_left} days.",
                "severity": "info",
                "remediation": "No action needed."
            })
            passed_checks.append("Certificate Expiration")
            score += 10
        elif days_left >= 0:
            findings.append({
                "check_name": "Certificate Expiration",
                "status": "fail",
                "details": f"Certificate expires soon: {days_left} days left.",
                "severity": "medium",
                "remediation": "Renew the SSL/TLS certificate before expiration."
            })
            failed_checks.append("Certificate Expiration")
            score -= 10
        else:
            findings.append({
                "check_name": "Certificate Expiration",
                "status": "fail",
                "details": "Certificate has expired.",
                "severity": "high",
                "remediation": "Renew and replace the expired SSL/TLS certificate immediately."
            })
            failed_checks.append("Certificate Expiration")
            score -= 20

        if cipher:
            cipher_name, protocol, bits = cipher

            if bits >= 128:
                findings.append({
                    "check_name": "Cipher Strength",
                    "status": "pass",
                    "details": f"Strong cipher in use: {cipher_name}, protocol: {protocol}, bits: {bits}.",
                    "severity": "info",
                    "remediation": "No action needed."
                })
                passed_checks.append("Cipher Strength")
                score += 10
            else:
                findings.append({
                    "check_name": "Cipher Strength",
                    "status": "fail",
                    "details": f"Weak cipher detected: {cipher_name}, protocol: {protocol}, bits: {bits}.",
                    "severity": "medium",
                    "remediation": "Disable weak ciphers and use modern TLS configurations."
                })
                failed_checks.append("Cipher Strength")
                score -= 10

        findings.append({
            "check_name": "Certificate Issuer",
            "status": "info",
            "details": f"Issuer: {issuer}",
            "severity": "info",
            "remediation": "No action needed."
        })

    except ssl.SSLError as e:
        findings.append({
            "check_name": "SSL/TLS Connection",
            "status": "fail",
            "details": f"SSL error: {str(e)}",
            "severity": "high",
            "remediation": "Review certificate validity and TLS server configuration."
        })
        failed_checks.append("SSL/TLS Connection")
        score -= 20

    except Exception as e:
        findings.append({
            "check_name": "SSL/TLS Connection",
            "status": "fail",
            "details": f"Could not inspect SSL/TLS: {str(e)}",
            "severity": "medium",
            "remediation": "Verify the site supports HTTPS and allows secure connections."
        })
        failed_checks.append("SSL/TLS Connection")
        score -= 10

    return {
        "category": "ssl_tls",
        "score_delta": score,
        "findings": findings,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks
    }