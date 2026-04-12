import json
from scanner.engine import run_scan

if __name__ == "__main__":
    url = input("Enter website URL: ").strip()
    result = run_scan(url)

    print("\n===== VULNSCAN LITE REPORT =====\n")
    print(json.dumps(result, indent=4, default=str))