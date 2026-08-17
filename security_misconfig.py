import requests

HEADERS_TO_CHECK = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Access-Control-Allow-Origin",
]

def check_security_misconfig(url):
    print(f"\n[*] Scanning: {url}")
    response = requests.get(url, verify=False)
    results = []

    for header in HEADERS_TO_CHECK:
        if header not in response.headers:
            results.append({
                "vulnerability": "Security Misconfiguration",
                "missing_header": header,
                "severity": "Medium",
                "status": "FAIL"
            })
            print(f"  [FAIL] Missing header: {header}")
        else:
            print(f"  [PASS] Found: {header}")

    return results