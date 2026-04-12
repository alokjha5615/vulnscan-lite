from scanner.utils import normalize_url, fetch_url
from scanner.headers_check import check_security_headers
from scanner.ssl_check import check_ssl_tls
from scanner.cms_check import check_cms
from scanner.scoring import calculate_final_score


def run_scan(input_url: str) -> dict:
    """
    Main passive scan engine.
    """

    normalized_url = normalize_url(input_url)
    fetch_result = fetch_url(normalized_url)

    report = {
        "target": normalized_url,
        "success": fetch_result["success"],
        "status_code": fetch_result["status_code"],
        "final_url": fetch_result["final_url"],
        "error": fetch_result["error"],
        "modules": [],
        "summary": {}
    }

    if not fetch_result["success"]:
        report["summary"] = {
            "score": 0,
            "grade": "F",
            "passed_checks": [],
            "failed_checks": ["Could not fetch target website"]
        }
        return report

    headers_module = check_security_headers(fetch_result["headers"])
    ssl_module = check_ssl_tls(fetch_result["final_url"])
    cms_module = check_cms(fetch_result["headers"], fetch_result["html"])

    modules = [headers_module, ssl_module, cms_module]
    scoring = calculate_final_score(modules)

    all_passed = []
    all_failed = []
    all_findings = []

    for module in modules:
        all_passed.extend(module.get("passed_checks", []))
        all_failed.extend(module.get("failed_checks", []))
        all_findings.extend(module.get("findings", []))

    report["modules"] = modules
    report["summary"] = {
        "score": scoring["score"],
        "grade": scoring["grade"],
        "passed_checks": all_passed,
        "failed_checks": all_failed,
        "total_findings": len(all_findings)
    }

    return report