import requests
import time
import random
import sys
import threading

# Configuration
TARGET_URL = "http://localhost:8000"
NORMAL_PATHS = [
    "/",
    "/about",
    "/contact",
    "/login",
    "/assets/style.css",
    "/images/logo.png"
]

MALICIOUS_URL_PAYLOADS = [
    "/admin/config.php?source=123.123.123.123",
    "/../../etc/passwd",
    "/.git/config",
    "/cgi-bin/test-cgi?val=../../../../bin/ls",
    "/phpmyadmin/scripts/setup.php",
    "/wp-login.php?action=register"
]

SQLI_PAYLOADS = [
    "/?id=1' OR '1'='1",
    "/login?user=admin' --",
    "/search?q=union select 1,2,3",
    "/api/users?id=1; DROP TABLE users",
    "/?cat=1 AND 1=1"
]

def log(message, color="WHITE"):
    colors = {
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "RESET": "\033[0m"
    }
    print(f"{colors.get(color, '')}{message}{colors['RESET']}")

def simulate_normal_user():
    """Simulate a normal user browsing the site"""
    log("\n[+] Simulating NORMAL USER...", "BLUE")
    for _ in range(3):
        path = random.choice(NORMAL_PATHS)
        url = f"{TARGET_URL}{path}"
        try:
            start_time = time.time()
            response = requests.get(url, timeout=5)
            elapsed = time.time() - start_time
            log(f"    GET {path} -> Status: {response.status_code} (Time: {elapsed:.2f}s)", "GREEN")
        except requests.exceptions.RequestException as e:
            log(f"    GET {path} -> FAILED: {e}", "RED")
        time.sleep(1)

def simulate_malicious_url_attack():
    """Simulate an attacker trying malicious URLs (Detected by AI Model V1)"""
    log("\n[!] Simulating MALICIOUS URL ATTACK (Targeting AI Model V1)...", "YELLOW")
    path = random.choice(MALICIOUS_URL_PAYLOADS)
    url = f"{TARGET_URL}{path}"
    
    log(f"    Sending malicious URL: {path}", "YELLOW")
    try:
        start_time = time.time()
        # Short timeout because we expect tarpit to delay it indefinitely
        requests.get(url, timeout=5)
        elapsed = time.time() - start_time
        log(f"    [FAILED] Server responded normally in {elapsed:.2f}s. Tarpit NOT activated?", "RED")
    except requests.exceptions.ReadTimeout:
        log(f"    [SUCCESS] Connection timed out! Tarpit is ACTIVE.", "GREEN")
    except Exception as e:
        log(f"    [INFO] Connection status: {e}", "GREEN")

def simulate_sqli_attack():
    """Simulate an attacker trying SQL Injection (Detected by AI Model V2)"""
    log("\n[!] Simulating SQL INJECTION ATTACK (Targeting AI Model V2)...", "YELLOW")
    path = random.choice(SQLI_PAYLOADS)
    # URL encode problematic characters manually if needed, but requests handles basic encoding
    url = f"{TARGET_URL}{path}"
    
    log(f"    Sending SQLi Payload: {path}", "YELLOW")
    try:
        start_time = time.time()
        requests.get(url, timeout=5)
        elapsed = time.time() - start_time
        log(f"    [FAILED] Server responded normally in {elapsed:.2f}s. Tarpit NOT activated?", "RED")
    except requests.exceptions.ReadTimeout:
        log(f"    [SUCCESS] Connection timed out! Tarpit is ACTIVE.", "GREEN")
    except Exception as e:
        log(f"    [INFO] Connection status: {e}", "GREEN")

def simulate_behavior_attack():
    """Simulate a request with anomalous behavior (Targeting AI Model V3/V4)"""
    log("\n[!] Simulating ANOMALOUS BEHAVIOR ATTACK (Targeting AI Layer 3 & 4)...", "YELLOW")
    
    # Construct a URL that looks structurally anomalous (long, many params, special chars)
    # but isn't necessarily a known SQLi or Phishing signature
    base = "/search"
    params = "&".join([f"param{i}=value{i}" for i in range(20)])
    special = "><;()@!#" * 5
    path = f"{base}?q={special}&{params}"
    url = f"{TARGET_URL}{path}"
    
    log(f"    Sending Anomalous Request: {path[:50]}...", "YELLOW")
    try:
        start_time = time.time()
        requests.get(url, timeout=5)
        elapsed = time.time() - start_time
        log(f"    [FAILED] Server responded normally in {elapsed:.2f}s. Tarpit NOT activated?", "RED")
    except requests.exceptions.ReadTimeout:
        log(f"    [SUCCESS] Connection timed out! Tarpit is ACTIVE (Behavior Detected).", "GREEN")
    except Exception as e:
        log(f"    [INFO] Connection status: {e}", "GREEN")

def main():
    log("╔════════════════════════════════════════════════════════╗", "RED")
    log("║       S.C.A.R. ATTACK SIMULATION TOOL v1.0             ║", "RED")
    log("╚════════════════════════════════════════════════════════╝", "RED")
    
    # Check if server is up
    try:
        requests.get(TARGET_URL, timeout=2)
        log("[*] Server is ONLINE. Starting simulation...", "GREEN")
    except:
        log(f"[!] Target server {TARGET_URL} is DOWN. Please start server.py first.", "RED")
        return

    # 1. Normal User
    simulate_normal_user()
    
    # 2. Malicious URL Attack
    simulate_malicious_url_attack()
    
    # 3. SQL Injection Attack
    simulate_sqli_attack()

    # 4. Behavioral Anomaly Attack
    simulate_behavior_attack()
    
    log("\n[=] Simulation Complete. Check logs on server side.", "BLUE")

if __name__ == "__main__":
    try:
        # Allow custom URL via arg
        if len(sys.argv) > 1:
            TARGET_URL = sys.argv[1]
        main()
    except KeyboardInterrupt:
        log("\n[!] Simulation stopped.", "RED")
