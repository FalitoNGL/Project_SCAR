#!/usr/bin/env python3
"""
██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗    ███████╗ ██████╗ █████╗ ██████╗ 
██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗██╔══██╗
██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║       ███████╗██║     ███████║██████╔╝
██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║       ╚════██║██║     ██╔══██║██╔══██╗
██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║       ███████║╚██████╗██║  ██║██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
    
    S.C.A.R. - System for Countering Automated Reconnaissance
    Active Defense Honeypot with Multi-Layer AI Fusion Engine
    
    Author: PROJECT S.C.A.R.
    Purpose: AI-powered active defense honeypot system
"""

import warnings
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

import argparse
import json
import os
import time
import random
import secrets
import ipaddress
import threading
import re
import pickle
import logging
import pandas as pd
import numpy as np
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlparse, parse_qs
import requests 
import socketserver

# ============================================================================
# ============================================================================
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ============================================================================
# ============================================================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_MAGENTA = '\033[45m'

# ============================================================================
# ============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(SCRIPT_DIR, "models")

class ThreatFusionEngine:
    def __init__(self):
        self.models = {
            "url": None,
            "sqli": None,
            "behavior": None,
            "anomaly": None
        }
        self.vectorizers = {
            "url": None,
            "sqli": None
        }
        self.load_models()

    def load_models(self):
        print(f"{Colors.MAGENTA}[*] Initializing Threat Fusion Engine...{Colors.RESET}")
        
        try:
            with open(os.path.join(MODELS_DIR, "url_model.pkl"), 'rb') as f:
                self.models["url"] = pickle.load(f)
            with open(os.path.join(MODELS_DIR, "url_vectorizer.pkl"), 'rb') as f:
                self.vectorizers["url"] = pickle.load(f)
            print(f"{Colors.GREEN}[+] Layer 1 (URL): ONLINE{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Layer 1 (URL) Failed: {e}{Colors.RESET}")

        try:
            with open(os.path.join(MODELS_DIR, "sqli_model.pkl"), 'rb') as f:
                self.models["sqli"] = pickle.load(f)
            with open(os.path.join(MODELS_DIR, "sqli_vectorizer.pkl"), 'rb') as f:
                self.vectorizers["sqli"] = pickle.load(f)
            print(f"{Colors.GREEN}[+] Layer 2 (SQLi): ONLINE{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Layer 2 (SQLi) Failed: {e}{Colors.RESET}")

        try:
            with open(os.path.join(MODELS_DIR, "behavior_model.pkl"), 'rb') as f:
                self.models["behavior"] = pickle.load(f)
            print(f"{Colors.GREEN}[+] Layer 3 (Behavior): ONLINE{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Layer 3 (Behavior) Failed: {e}{Colors.RESET}")

        try:
            with open(os.path.join(MODELS_DIR, "anomaly_model.pkl"), 'rb') as f:
                self.models["anomaly"] = pickle.load(f)
            print(f"{Colors.GREEN}[+] Layer 4 (Anomaly): ONLINE{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Layer 4 (Anomaly) Failed: {e}{Colors.RESET}")

    def analyze_url(self, url):
        if not self.models["url"] or not self.vectorizers["url"]:
            return 0.0, "Inactive"
        try:
            vec = self.vectorizers["url"].transform([url])
            prob = self.models["url"].predict_proba(vec)[0]
            pred_class = self.models["url"].predict(vec)[0]
            confidence = np.max(prob)
            
            if pred_class == 'benign':
                return 0.0, "Benign"
            else:
                return confidence, pred_class
        except Exception as e:
            return 0.0, "Error"

    def analyze_sqli(self, payload):
        if not self.models["sqli"] or not self.vectorizers["sqli"]:
            return 0.0
        try:
            if not payload: return 0.0
            vec = self.vectorizers["sqli"].transform([str(payload)])
            prob = self.models["sqli"].predict_proba(vec)[0][1] # prob of class 1
            return prob
        except Exception:
            return 0.0

    def analyze_behavior(self, method, url, query):
        if not self.models["behavior"]:
            return 0.0
        try:
            parsed_url = urlparse(url)
            path = parsed_url.path
            
            method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5}
            method_idx = method_map.get(method, 0)
            
            features = [
                method_idx,
                len(url),
                len(path),
                len(query),
                len(parse_qs(query)),
                sum(url.count(c) for c in ['%', "'", '"', '<', '>', ';', '(', ')', '=']),
                path.count('/')
            ]
            
            pred = self.models["behavior"].predict([features])[0]
            return float(pred)
        except Exception:
            return 0.0
            
    def analyze_anomaly(self, method, url, query):
        if not self.models["anomaly"]:
            return 1 # 1 is Inlier (Normal) in Isolation Forest, -1 is Outlier
        try:
            parsed_url = urlparse(url)
            path = parsed_url.path
            
            method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5}
            method_idx = method_map.get(method, 0)
            
            features = [
                method_idx,
                len(url),
                len(path),
                len(query),
                len(parse_qs(query)),
                sum(url.count(c) for c in ['%', "'", '"', '<', '>', ';', '(', ')', '=']),
                path.count('/')
            ]
            
            pred = self.models["anomaly"].predict([features])[0]
            return pred
        except Exception:
            return 1

    def scan_request(self, method, url, body=""):
        url_score, url_type = self.analyze_url(url)
        
        parsed = urlparse(url)
        sqli_score_query = self.analyze_sqli(parsed.query)
        sqli_score_body = self.analyze_sqli(body)
        sqli_score = max(sqli_score_query, sqli_score_body)
        
        parsed = urlparse(url)
        behav_score = self.analyze_behavior(method, url, parsed.query)
        
        anomaly_res = self.analyze_anomaly(method, url, parsed.query)
        anomaly_score = 1.0 if anomaly_res == -1 else 0.0
        
        is_threat = False
        reasons = []
        hard_flags = 0  # URL, SQLi (high confidence, can trigger alone)
        soft_flags = 0  # Behavior, Anomaly (supplementary, need confirmation)
        
        if url_score > 0.8:
            hard_flags += 1
            reasons.append(f"Malicious URL ({url_type}: {url_score:.2f})")
            
        if sqli_score > 0.8:
            hard_flags += 1
            reasons.append(f"SQL Injection ({sqli_score:.2f})")
            
        if behav_score > 0.5:
            soft_flags += 1
            reasons.append("Suspicious Behavior Pattern")
            
        if anomaly_score > 0.5:
            soft_flags += 1
            reasons.append("Traffic Anomaly Detected")
        
        if hard_flags > 0:
            is_threat = True
        elif soft_flags >= 2:
            is_threat = True
        
        total_risk = (url_score + sqli_score + behav_score + anomaly_score) / 4.0
        
        return is_threat, reasons, total_risk

# ============================================================================
# ============================================================================
ABUSEIPDB_API_KEY = "8a0456564e5ea90f807a1b68be09b677d18359d92cd272d7c2b0767ab0b9392018bb20c62e0a3df3"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_CONFIDENCE_THRESHOLD = 50
SCAR_HEADERS = {
    "Server": "SCAR-Active-Defense",
    "X-Counter-Measure": "Active",
    "X-Powered-By": "S.C.A.R. Defense Grid",
    "X-Defense-Status": "ARMED",
}
TARPIT_DELAY_SECONDS = 5
TARPIT_HEADER_COUNT = 1000000
IP_CACHE = {}
IP_CACHE_LOCK = threading.Lock()
CACHE_TTL_SECONDS = 3600

TELEGRAM_BOT_TOKEN = "8012805045:AAGe4PmBOxqxhF-LxCwTV4fBAb476uZHe7Y"
TELEGRAM_CHAT_ID = "-5116169252"
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)

def send_telegram_alert(ip, reasons, risk_score=0.0):
    """Send threat alert to Telegram (non-blocking background thread)"""
    if not TELEGRAM_ENABLED:
        return
    
    def _send():
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            reason_list = "\n".join([f"  • {r}" for r in reasons])
            risk_bar = "🔴" * int(risk_score * 5) + "⚪" * (5 - int(risk_score * 5))
            
            message = (
                f"🚨 *S.C.A.R. THREAT ALERT*\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"⏰ Time: `{timestamp}`\n"
                f"🌐 Attacker IP: `{ip}`\n"
                f"⚠️ Risk Level: {risk_bar} ({risk_score:.0%})\n\n"
                f"📋 *Threat Details:*\n{reason_list}\n\n"
                f"⚔️ *Action:* Tarpit Engaged (Draining Resources)\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"🛡️ _S.C.A.R. Defense Grid_"
            )
            
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "Markdown"
            }
            resp = requests.post(url, json=data, timeout=5)
            if resp.status_code == 200:
                print(f"{Colors.CYAN}[TELEGRAM] Alert sent for {ip}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[TELEGRAM] Failed: {resp.status_code}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[TELEGRAM] Error: {e}{Colors.RESET}")
    
    threading.Thread(target=_send, daemon=True).start()

fusion_engine = None

def is_private_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return True

def check_ip_reputation(ip_address):
    if is_private_ip(ip_address):
        print(f"{Colors.CYAN}[IP-SCAN] {ip_address} is Private/Loopback - Skipping AbuseIPDB{Colors.RESET}")
        return False, 0, "private"
        
    with IP_CACHE_LOCK:
        if ip_address in IP_CACHE:
            cached = IP_CACHE[ip_address]
            if time.time() - cached["timestamp"] < CACHE_TTL_SECONDS:
                print(f"{Colors.YELLOW}[CACHE] {ip_address} Score: {cached['score']}{Colors.RESET}")
                return cached["is_bad"], cached["score"], "cache"
    
    return False, 0, "api-mock" 

# ============================================================================
# ============================================================================
class CustomHandler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass # Suppress client disconnect errors (common with scanners)
        except Exception as e:
            print(f"{Colors.RED}[!] Request Error: {e}{Colors.RESET}")

    def generate_garbage_header(self):
        random_id = random.randint(100000, 999999)
        random_hex = secrets.token_hex(32)
        return f"X-Trap-{random_id}", random_hex

    def execute_tarpit(self, client_ip, reasons, risk_score=0.0):
        print(f"\n{Colors.BG_RED}{Colors.WHITE} ⚠️ THREAT DETECTED: {client_ip} → TARPIT ENGAGED {Colors.RESET}")
        print(f"{Colors.RED}Reasons: {', '.join(reasons)}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Draining attacker resources...{Colors.RESET}")
        logging.warning(f"TARPIT ENGAGED: IP={client_ip} Reasons={reasons}")
        
        send_telegram_alert(client_ip, reasons, risk_score)
        
        try:
            self.wfile.write(b"HTTP/1.1 200 OK\r\n")
            for k, v in SCAR_HEADERS.items():
                self.wfile.write(f"{k}: {v}\r\n".encode())
            self.wfile.write(b"Content-Type: text/html\r\n")
            self.wfile.write(b"Transfer-Encoding: chunked\r\n\r\n")
            
            count = 0
            while count < TARPIT_HEADER_COUNT:
                k, v = self.generate_garbage_header()
                data = f"{k}: {v}\r\n"
                
                chunk_size = hex(len(data))[2:]
                valid_chunk = f"{chunk_size}\r\n{data}\r\n"
                
                self.wfile.write(valid_chunk.encode())
                self.wfile.flush()
                count += 1
                time.sleep(TARPIT_DELAY_SECONDS)
                if count % 10 == 0:
                    print(f"\r{Colors.MAGENTA}[TARPIT] Sent {count} valid chunks to {client_ip}{Colors.RESET}", end="")
        except Exception:
            print(f"\n{Colors.GREEN}[✔] Attacker disconnected. Resources drained successfully.{Colors.RESET}")

    def handle_request(self):
        client_ip = self.client_address[0]
        method = self.command
        path = self.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else ""
        
        print(f"\n{Colors.BLUE}[REQ] {method} {path} from {client_ip}{Colors.RESET}")
        
        is_bad_ip, score, src = check_ip_reputation(client_ip)
        if is_bad_ip:
            self.execute_tarpit(client_ip, [f"Bad Reputation (Score: {score})"], risk_score=score/100.0)
            return

        RECON_PATHS = [
            '.git', '.env', '.htaccess', '.htpasswd', '.svn', '.DS_Store',
            'wp-admin', 'wp-login', 'wp-content', 'wp-includes',
            'phpmyadmin', 'phpMyAdmin', 'adminer',
            '/admin', '/administrator', '/cpanel', '/cPanel',
            'etc/passwd', 'etc/shadow',
            'config.php', 'database.yml', 'settings.py',
            '../', '..\\',
            '/shell', '/cmd', '/console',
            'backup', '.bak', '.sql', '.dump',
        ]
        path_lower = path.lower()
        matched_recon = [p for p in RECON_PATHS if p.lower() in path_lower]
        if matched_recon:
            recon_reasons = [f"Reconnaissance Probe ({', '.join(matched_recon)})"]
            print(f"{Colors.RED}[RECON] Sensitive path detected: {matched_recon}{Colors.RESET}")
            self.execute_tarpit(client_ip, recon_reasons, risk_score=0.9)
            return

        is_threat, reasons, risk = fusion_engine.scan_request(method, path, body)
        
        if is_threat or risk > 0.7:
            print(f"{Colors.RED}[AI-FUSION] RISK: {risk:.2f} | {reasons}{Colors.RESET}")
            self.execute_tarpit(client_ip, reasons, risk_score=risk)
            return
        elif reasons:
            print(f"{Colors.YELLOW}[AI-WARN] Low Risk ({risk:.2f}): {reasons} — Allowing{Colors.RESET}")
            logging.info(f"SOFT-WARN: {method} {path} from {client_ip} | {reasons}")
        
        print(f"{Colors.GREEN}[CLEAN] Request allowed. serving content.{Colors.RESET}")
        logging.info(f"ALLOWED: {method} {path} from {client_ip}")
        
        try:
            with open("default.html", "rb") as f:
                content = f.read()
        except:
            content = b"<h1>Access Denied</h1>"

        self.send_response(200)
        for k, v in SCAR_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_HEAD(self): self.handle_request()
    def do_OPTIONS(self): self.handle_request()

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def run_server(port=8080):
    global fusion_engine
    
    print(f"{Colors.CYAN}")
    print("╔════════════════════════════════════════════╗")
    print("║   S.C.A.R. MULTI-LAYER AI DEFENSE SYSTEM   ║")
    print("╚════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    fusion_engine = ThreatFusionEngine()
    
    server = ThreadedHTTPServer(('0.0.0.0', port), CustomHandler)
    print(f"\n{Colors.GREEN}[*] Server listening on port {port}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Fusion Engine: ACTIVE{Colors.RESET}")
    if TELEGRAM_ENABLED:
        print(f"{Colors.GREEN}[*] Telegram Alerts: ACTIVE ✅{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Telegram Alerts: DISABLED (No token/chat_id){Colors.RESET}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    run_server(args.port)
