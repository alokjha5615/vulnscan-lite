from bs4 import BeautifulSoup
import re


def check_cms(headers: dict, html: str) -> dict:
    """
    Detect CMS clues from:
    - meta generator tags
    - X-Powered-By header
    - common HTML patterns
    """

    findings = []
    passed_checks = []
    failed_checks = []
    score = 0

    detected_cms = None
    detected_version = None

    soup = BeautifulSoup(html, "html.parser")

    generator_tag = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
    x_powered_by = headers.get("X-Powered-By", "")

    if generator_tag and generator_tag.get("content"):
        generator_content = generator_tag.get("content").strip()

        findings.append({
            "check_name": "Meta Generator Tag",
            "status": "info",
            "details": f"Generator meta tag found: {generator_content}",
            "severity": "info",
            "remediation": "Consider hiding generator/version details if not needed publicly."
        })

        lower_content = generator_content.lower()

        if "wordpress" in lower_content:
            detected_cms = "WordPress"
        elif "drupal" in lower_content:
            detected_cms = "Drupal"
        elif "joomla" in lower_content:
            detected_cms = "Joomla"

        version_match = re.search(r"(\d+(\.\d+)+)", generator_content)
        if version_match:
            detected_version = version_match.group(1)

    if x_powered_by:
        findings.append({
            "check_name": "X-Powered-By Header",
            "status": "info",
            "details": f"X-Powered-By exposed: {x_powered_by}",
            "severity": "low",
            "remediation": "Hide or remove X-Powered-By header to reduce technology exposure."
        })
        failed_checks.append("X-Powered-By Exposure")
        score -= 5

        lower_powered = x_powered_by.lower()
        if "php" in lower_powered and not detected_cms:
            detected_cms = "PHP-based site"
        elif "asp.net" in lower_powered and not detected_cms:
            detected_cms = "ASP.NET"
        elif "express" in lower_powered and not detected_cms:
            detected_cms = "Node.js / Express"

    html_lower = html.lower()

    if not detected_cms:
        if "wp-content" in html_lower or "wp-includes" in html_lower:
            detected_cms = "WordPress"
        elif "/sites/default/" in html_lower:
            detected_cms = "Drupal"
        elif "joomla" in html_lower:
            detected_cms = "Joomla"

    if detected_cms:
        detail = f"Possible CMS detected: {detected_cms}"
        if detected_version:
            detail += f" (version: {detected_version})"

        findings.append({
            "check_name": "CMS Detection",
            "status": "info",
            "details": detail,
            "severity": "info",
            "remediation": "Keep CMS/plugins updated and avoid exposing exact versions where possible."
        })

        if detected_version:
            findings.append({
                "check_name": "CMS Version Exposure",
                "status": "fail",
                "details": f"CMS version appears publicly exposed: {detected_version}",
                "severity": "medium",
                "remediation": "Hide public version details and ensure the CMS is fully updated."
            })
            failed_checks.append("CMS Version Exposure")
            score -= 10
        else:
            passed_checks.append("CMS Detection")
            score += 5
    else:
        findings.append({
            "check_name": "CMS Detection",
            "status": "pass",
            "details": "No obvious CMS fingerprint detected.",
            "severity": "info",
            "remediation": "No action needed."
        })
        passed_checks.append("CMS Detection")
        score += 10

    return {
        "category": "cms_detection",
        "score_delta": score,
        "findings": findings,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "detected_cms": detected_cms,
        "detected_version": detected_version
    }