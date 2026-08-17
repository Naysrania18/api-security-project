import requests

def check_excessive_data(url, headers=None):
    print(f"\n[*] Testing Excessive Data Exposure: {url}")
    results = []
    
    # If no token is provided, safely default to an empty dictionary
    if headers is None:
        headers = {}
    
    # Test 1 — Get user profile
    r1 = requests.get(f"{url}/identity/api/v2/user/profile", verify=False)
    if r1.status_code == 200:
        try:
            data = r1.json()
            sensitive_fields = ['ssn', 'social_security', 'credit_card', 'cvv', 'password', 'secret', 'token']
            exposed = []
            for field in sensitive_fields:
                if field in str(data).lower():
                    exposed.append(field)
            
            if exposed:
                results.append({
                    "vulnerability": "Excessive Data Exposure",
                    "test": "Sensitive data exposed in /profile",
                    "severity": "High",
                    "status": "FAIL",
                    "detail": f"Exposed fields: {exposed}"
                })
                print(f"  [FAIL] Sensitive data exposed: {exposed}")
            else:
                results.append({
                    "vulnerability": "Excessive Data Exposure",
                    "test": "Sensitive data exposed in /profile",
                    "severity": "High",
                    "status": "PASS",
                    "detail": "No sensitive fields found"
                })
                print("  [PASS] No obvious sensitive data exposed")
        except:
            results.append({
                "vulnerability": "Excessive Data Exposure",
                "test": "Sensitive data exposed in /profile",
                "severity": "High",
                "status": "INFO",
                "detail": "Response not JSON"
            })
            print("  [INFO] Response not JSON")
    else:
        results.append({
            "vulnerability": "Excessive Data Exposure",
            "test": "Sensitive data exposed in /profile",
            "severity": "High",
            "status": "INFO",
            "detail": f"Returned {r1.status_code} — requires authentication"
        })
        print(f"  [INFO] /profile returned {r1.status_code}")
    
    # Test 2 — Get all users
    r2 = requests.get(f"{url}/identity/api/v2/users", verify=False)
    if r2.status_code == 200:
        try:
            data = r2.json()
            if len(str(data)) > 1000:
                results.append({
                    "vulnerability": "Excessive Data Exposure",
                    "test": "Large data response in /users",
                    "severity": "Medium",
                    "status": "FAIL",
                    "detail": f"Response size: {len(str(data))} bytes"
                })
                print(f"  [FAIL] Excessive data returned: {len(str(data))} bytes")
            else:
                results.append({
                    "vulnerability": "Excessive Data Exposure",
                    "test": "Large data response in /users",
                    "severity": "Medium",
                    "status": "PASS",
                    "detail": f"Response size: {len(str(data))} bytes — normal"
                })
                print("  [PASS] Normal response size")
        except:
            results.append({
                "vulnerability": "Excessive Data Exposure",
                "test": "Large data response in /users",
                "severity": "Medium",
                "status": "INFO",
                "detail": "Response not JSON"
            })
            print("  [INFO] Response not JSON")
    else:
        results.append({
            "vulnerability": "Excessive Data Exposure",
            "test": "Large data response in /users",
            "severity": "Medium",
            "status": "INFO",
            "detail": f"Returned {r2.status_code} — requires authentication"
        })
        print(f"  [INFO] /users returned {r2.status_code}")
    
    return results