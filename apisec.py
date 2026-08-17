import json
import requests
from modules.security_misconfig import check_security_misconfig
from modules.broken_auth import check_broken_auth
from modules.excessive_data import check_excessive_data
from modules.injection import check_injection
from modules.bola import check_bola

TARGET = "http://localhost:8888"

def get_auth_headers(base_url):
    """Directly authenticates with crAPI using your pre-created admin account."""
    login_url = f"{base_url}/identity/api/auth/login"
    test_credentials = {
        "email": "admin@example.com",
        "password": "YourAdminPasswordHere"  # <-- Make sure this matches your actual password!
    }
    try:
        print(f"[*] Authenticating with existing context ({test_credentials['email']})...")
        response = requests.post(login_url, json=test_credentials, timeout=5)
        if response.status_code == 200:
            token = response.json().get("token")
            print("[+] Authentication successful. Authorization Token provisioned.")
            return {"Authorization": f"Bearer {token}"}
        else:
            print(f"[-] Authentication failed (Status: {response.status_code}). Scanning unauthenticated.")
            return {}
    except Exception as e:
        print(f"[-] Connection exception during authentication: {e}. Scanning unauthenticated.")
        return {}

# --- MAIN EXECUTION TRACE ---
# 1. Fetch the authentication headers before running tests
headers = get_auth_headers(TARGET)

all_results = []

print("\n[*] Starting API Security Testing Framework Execution...")

# 2. Run the modules, passing the auth headers correctly
all_results += check_security_misconfig(TARGET)
all_results += check_broken_auth(TARGET)
all_results += check_excessive_data(TARGET, headers=headers)
all_results += check_bola(TARGET, user_a_token=headers)
all_results += check_injection(TARGET)

# 3. Save the results file
with open("results/report.json", "w") as f:
    json.dump(all_results, f, indent=2)

print("\n[+] Scan complete. Report saved to results/report.json")
