import requests
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme. Default to https:// if missing.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_hostname(url: str) -> str:
    """
    Extract hostname from a URL.
    """
    parsed = urlparse(url)
    return parsed.hostname


def fetch_url(url: str, timeout: int = 10) -> dict:
    """
    Fetch a URL safely and return response details.
    This is passive analysis only.
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "VulnScanLite/1.0 (Passive Security Scanner)"
            }
        )

        return {
            "success": True,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "html": response.text,
            "error": None
        }

    except requests.exceptions.SSLError as e:
        return {
            "success": False,
            "final_url": url,
            "status_code": None,
            "headers": {},
            "html": "",
            "error": f"SSL error: {str(e)}"
        }

    except requests.exceptions.ConnectionError as e:
        return {
            "success": False,
            "final_url": url,
            "status_code": None,
            "headers": {},
            "html": "",
            "error": f"Connection error: {str(e)}"
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "final_url": url,
            "status_code": None,
            "headers": {},
            "html": "",
            "error": "Request timed out"
        }

    except Exception as e:
        return {
            "success": False,
            "final_url": url,
            "status_code": None,
            "headers": {},
            "html": "",
            "error": f"Unexpected error: {str(e)}"
        }