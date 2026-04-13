from bs4 import BeautifulSoup
import re


CMS_BASELINES = {
    "wordpress": "6.0",
    "drupal": "9.0",
    "joomla": "4.0"
}


def is_outdated(detected_version: str, baseline_version: str) -> bool:
    try:
        dv = [int(x) for x in detected_version.split(".") if x.isdigit()]
        bv = [int(x) for x in baseline_version.split(".") if x.isdigit()]

        length = max(len(dv), len(bv))
        dv += [0] * (length - len(dv))
        bv += [0] * (length - len(bv))

        return dv < bv
    except Exception:
        return False


def check_cms(headers: dict, html: str) -> dict:
    """
    Detect CMS clues from:
    - meta generator tags
    - X-Powered-By header
    - common HTML patterns

    Also flags potentially outdated CMS versions when a visible version
    is below the configured baseline.
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

    # Detect from meta generator
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

    # Detect from X-Powered-By
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

    # Detect from common HTML fingerprints
    html_lower = html.lower()

    if not detected_cms:
        if "wp-content" in html_lower or "wp-includes" in html_lower:
            detected_cms = "WordPress"
        elif "/sites/default/" in html_lower:
            detected_cms = "Drupal"
        elif "joomla" in html_lower:
            detected_cms = "Joomla"

    outdated_flag = False
    outdated_note = None

    if detected_cms and detected_version:
        cms_key = detected_cms.lower()

        if cms_key in CMS_BASELINES:
            baseline = CMS_BASELINES[cms_key]

            if is_outdated(detected_version, baseline):
                outdated_flag = True
                outdated_note = (
                    f"{detected_cms} version {detected_version} may be outdated "
                    f"(baseline {baseline}+ recommended)."
                )

    # Final CMS findings
    if detected_cms:
        if detected_version:
            findings.append({
                "check_name": "CMS Version Exposure",
                "status": "info",
                "details": f"{detected_cms} version appears publicly exposed: {detected_version}",
                "severity": "medium",
                "remediation": "Hide public version details where possible and keep the CMS fully updated."
            })

        if outdated_flag:
            findings.append({
                "check_name": "CMS Version Status",
                "status": "fail",
                "details": outdated_note,
                "severity": "medium",
                "remediation": (
                    "Update the CMS to the latest stable version.\n"
                    "Ensure plugins/themes are also updated.\n"
                    "Regularly apply security patches."
                )
            })
            failed_checks.append("CMS Version Status")
            score -= 10
        else:
            findings.append({
                "check_name": "CMS Detection",
                "status": "pass",
                "details": (
                    f"{detected_cms} detected."
                    + (f" Version identified: {detected_version}." if detected_version else " No outdated version identified.")
                ),
                "severity": "info",
                "remediation": "No action needed."
            })
            passed_checks.append("CMS Detection")
            score += 10

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
        "detected_version": detected_version,
        "outdated": outdated_flag
    }