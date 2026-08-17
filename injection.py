import requests
import json

def check_injection(url):
    print(f"\n[*] Testing Injection Vulnerabilities: {url}")
    results = []
    
    # Test 1 — SQL Injection in login
    login_url = f"{url}/identity/api/v2/login"
    sql_payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--"]
    
    for payload in sql_payloads:
        test_data = {
            "email": f"admin@example.com{payload}",
            "password": "anything"
        }
        try:
            r = requests.post(login_url, json=test_data, verify=False)
            if r.status_code == 200 and "token" in r.text:
                results.append({
                    "vulnerability": "Injection",
                    "test": f"SQL Injection in login with: {payload}",
                    "severity": "Critical",
                    "status": "FAIL",
                    "detail": "Login bypassed with SQL injection"
                })
                print(f"  [FAIL] SQL Injection possible with: {payload}")
                break
        except:
            pass
    else:
        results.append({
            "vulnerability": "Injection",
            "test": "SQL Injection in login",
            "severity": "Critical",
            "status": "PASS",
            "detail": "SQL injection attempts blocked"
        })
        print("  [PASS] SQL Injection blocked")
    
    # Test 2 — NoSQL Injection
    nosql_payloads = [
        {"email": {"$ne": ""}, "password": {"$ne": ""}},
        {"email": {"$gt": ""}, "password": {"$gt": ""}}
    ]
    
    for payload in nosql_payloads:
        try:
            r = requests.post(login_url, json=payload, verify=False)
            if r.status_code == 200 and "token" in r.text:
                results.append({
                    "vulnerability": "Injection",
                    "test": f"NoSQL Injection with: {payload}",
                    "severity": "Critical",
                    "status": "FAIL",
                    "detail": "NoSQL injection bypassed login"
                })
                print(f"  [FAIL] NoSQL Injection possible")
                break
        except:
            pass
    else:
        results.append({
            "vulnerability": "Injection",
            "test": "NoSQL Injection",
            "severity": "Critical",
            "status": "PASS",
            "detail": "NoSQL injection attempts blocked"
        })
        print("  [PASS] NoSQL Injection blocked")
    
    # Test 3 — Command Injection
    cmd_payloads = ["; ls", "| dir", "& whoami"]
    
    for payload in cmd_payloads:
        try:
            r = requests.get(f"{url}/identity/api/v2/health?cmd={payload}", verify=False)
            if r.status_code == 200 and ("root" in r.text or "admin" in r.text or "user" in r.text):
                results.append({
                    "vulnerability": "Injection",
                    "test": f"Command Injection with: {payload}",
                    "severity": "Critical",
                    "status": "FAIL",
                    "detail": "Command execution detected"
                })
                print(f"  [FAIL] Command Injection possible")
                break
        except:
            pass
    else:
        results.append({
            "vulnerability": "Injection",
            "test": "Command Injection",
            "severity": "Critical",
            "status": "PASS",
            "detail": "Command injection attempts blocked"
        })
        print("  [PASS] Command Injection blocked")
    
    return results