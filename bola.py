import requests
import warnings
warnings.filterwarnings("ignore")

def check_bola(url, user_a_token=None, user_b_vehicle_id=None):
    print(f"\n[*] Testing BOLA (Broken Object Level Authorisation): {url}")
    results = []

    # If no tokens provided, use default test IDs for demonstration
    if user_b_vehicle_id is None:
        user_b_vehicle_id = 2  # Try to access vehicle ID 2

    # Test 1 — Access another user's vehicle location by ID manipulation
    headers = {}
    if user_a_token:
        headers = {"Authorization": f"Bearer {user_a_token}"}

    try:
        r1 = requests.get(
            f"{url}/api/v2/vehicle/{user_b_vehicle_id}/location",
            headers=headers,
            verify=False,
            timeout=10
        )
        if r1.status_code == 200:
            results.append({
                "vulnerability": "BOLA",
                "test": f"Cross-user vehicle access — vehicle ID {user_b_vehicle_id}",
                "endpoint": f"/api/v2/vehicle/{user_b_vehicle_id}/location",
                "severity": "Critical",
                "status": "FAIL",
                "detail": f"API returned HTTP 200 — vehicle data accessed without ownership verification"
            })
            print(f"  [FAIL] BOLA detected — vehicle ID {user_b_vehicle_id} accessible without authorisation")
        else:
            results.append({
                "vulnerability": "BOLA",
                "test": f"Cross-user vehicle access — vehicle ID {user_b_vehicle_id}",
                "endpoint": f"/api/v2/vehicle/{user_b_vehicle_id}/location",
                "severity": "Critical",
                "status": "PASS",
                "detail": f"API returned HTTP {r1.status_code} — access correctly denied"
            })
            print(f"  [PASS] Vehicle ID {user_b_vehicle_id} — access denied ({r1.status_code})")

    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] Could not connect to endpoint: {e}")
        results.append({
            "vulnerability": "BOLA",
            "test": "Cross-user vehicle access",
            "severity": "Critical",
            "status": "ERROR",
            "detail": str(e)
        })

    # Test 2 — Enumerate sequential IDs
    print(f"  [*] Testing sequential ID enumeration...")
    for vehicle_id in [1, 3, 4]:
        try:
            r2 = requests.get(
                f"{url}/api/v2/vehicle/{vehicle_id}/location",
                headers=headers,
                verify=False,
                timeout=10
            )
            if r2.status_code == 200:
                results.append({
                    "vulnerability": "BOLA",
                    "test": f"Sequential ID enumeration — vehicle ID {vehicle_id}",
                    "endpoint": f"/api/v2/vehicle/{vehicle_id}/location",
                    "severity": "Critical",
                    "status": "FAIL",
                    "detail": f"Vehicle ID {vehicle_id} returned HTTP 200 — BOLA vulnerability confirmed"
                })
                print(f"  [FAIL] Vehicle ID {vehicle_id} — data returned (BOLA confirmed)")
            else:
                print(f"  [PASS] Vehicle ID {vehicle_id} — access denied ({r2.status_code})")

        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] Vehicle ID {vehicle_id}: {e}")

    # Test 3 — Access another user's profile by ID.
    try:
        r3 = requests.get(
            f"{url}/identity/api/v2/user/2",
            headers=headers,
            verify=False,
            timeout=10
        )
        if r3.status_code == 200:
            results.append({
                "vulnerability": "BOLA",
                "test": "Cross-user profile access — user ID 2",
                "endpoint": "/identity/api/v2/user/2",
                "severity": "Critical",
                "status": "FAIL",
                "detail": "API returned HTTP 200 — user profile accessed without ownership check"
            })
            print(f"  [FAIL] User profile ID 2 — accessible without authorisation")
        else:
            print(f"  [PASS] User profile ID 2 — access denied ({r3.status_code})")

    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] User profile test: {e}")

    return results
