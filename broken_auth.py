import requests

def check_broken_auth(url):
    print(f"\n[*] Testing Broken Authentication: {url}")
    results = []
    
    # Test 1 — No token at all
    r1 = requests.get(f"{url}/identity/api/v2/user/dashboard", verify=False)
    if r1.status_code == 200:
        results.append({
            "vulnerability": "Broken Authentication",
            "test": "No token supplied",
            "severity": "High",
            "status": "FAIL",
            "detail": "API responded 200 without any token"
        })
        print("  [FAIL] No token — API still responded 200")
    else:
        results.append({
            "vulnerability": "Broken Authentication",
            "test": "No token supplied",
            "severity": "High",
            "status": "PASS",
            "detail": f"Returned {r1.status_code} — properly rejected"
        })
        print(f"  [PASS] No token — returned {r1.status_code}")

    # Test 2 — Invalid token
    headers_invalid = {"Authorization": "Bearer invalidtoken123"}
    r2 = requests.get(f"{url}/identity/api/v2/user/dashboard", headers=headers_invalid, verify=False)
    if r2.status_code == 200:
        results.append({
            "vulnerability": "Broken Authentication",
            "test": "Invalid token accepted",
            "severity": "High",
            "status": "FAIL",
            "detail": "API accepted an invalid bearer token"
        })
        print("  [FAIL] Invalid token accepted")
    else:
        results.append({
            "vulnerability": "Broken Authentication",
            "test": "Invalid token accepted",
            "severity": "High",
            "status": "PASS",
            "detail": f"Returned {r2.status_code} — properly rejected"
        })
        print(f"  [PASS] Invalid token rejected — {r2.status_code}")

    # Test 3 — Expired token
    expired = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTE2MjM5MDIyfQ.expired"
    headers_expired = {"Authorization": expired}
    r3 = requests.get(f"{url}/identity/api/v2/user/dashboard", headers=headers_expired, verify=False)
    if r3.status_code == 200:
        results.append({
            "vulnerability": "Broken Authentication",
            "test": "Expired token accepted",
            "severity": "High",
            "status": "FAIL",
            "detail": "API accepted an expired bearer token"
        })
        print("  [FAIL] Expired token accepted")
    else:
        results.append({
            "vulnerability": "Broken Authentication",
            "test": "Expired token accepted",
            "severity": "High",
            "status": "PASS",
            "detail": f"Returned {r3.status_code} — properly rejected"
        })
        print(f"  [PASS] Expired token rejected — {r3.status_code}")

    return results