import os
import subprocess
import time
from collections import defaultdict
from threading import Thread, Lock
import logging
import ipaddress  
import requests 

class AdvancedFirewall:
    GOOGLE_SAFE_BROWSING_API_KEY = "your_google_api_key"  

    def __init__(self):
        self.blacklist = set()
        self.whitelist = set()
        self.rate_limit = defaultdict(list)  
        self.rate_limit_threshold = 100  
        self.port_scan_threshold = 10  
        self.port_access_log = defaultdict(set)
        self.lock = Lock()

        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("firewall.log"),
                logging.StreamHandler()
            ]
        )

    def execute_iptables_command(self, command):
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing iptables command: {e}")

    def add_to_blacklist(self, ip):
        with self.lock:
            if ip not in self.blacklist:
                self.blacklist.add(ip)
                command = f"iptables -A INPUT -s {ip} -j DROP"
                self.execute_iptables_command(command)
                logging.info(f"Added {ip} to blacklist.")

    def remove_from_blacklist(self, ip):
        with self.lock:
            if ip in self.blacklist:
                self.blacklist.remove(ip)
                command = f"iptables -D INPUT -s {ip} -j DROP"
                self.execute_iptables_command(command)
                logging.info(f"Removed {ip} from blacklist.")

    def add_to_whitelist(self, ip):
        with self.lock:
            if ipaddress.ip_address(ip): 
                self.whitelist.add(ip)
                logging.info(f"Added {ip} to whitelist.")

    def log_access(self, ip, port):
        timestamp = time.time()
        with self.lock:

            self.rate_limit[ip].append(timestamp)
            self.rate_limit[ip] = [t for t in self.rate_limit[ip] if timestamp - t < 60]


            self.port_access_log[ip].add(port)

            if len(self.rate_limit[ip]) > self.rate_limit_threshold:
                logging.warning(f"Rate limit exceeded for {ip}. Adding to blacklist.")
                self.add_to_blacklist(ip)

            if len(self.port_access_log[ip]) > self.port_scan_threshold:
                logging.warning(f"Port scan detected from {ip}. Adding to blacklist.")
                self.add_to_blacklist(ip)

    def monitor_traffic(self):
        def parse_logs():
            while True:
                time.sleep(1)

                test_ip = "192.168.1.100"
                test_port = 8080
                self.log_access(test_ip, test_port)

        Thread(target=parse_logs, daemon=True).start()

    def manage_traffic_priority(self):
        high_priority_ips = ["192.168.1.10"]
        for ip in high_priority_ips:
            if ipaddress.ip_address(ip): 
                command = f"iptables -A INPUT -s {ip} -j ACCEPT"
                self.execute_iptables_command(command)
                logging.info(f"Prioritized traffic for {ip}.")

    def update_rules(self):
        while True:
            time.sleep(30)
            logging.info("Updating rules dynamically.")


    def check_url_safety(self, url):
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.GOOGLE_SAFE_BROWSING_API_KEY}"
            payload = {
                "client": {
                    "clientId": "your_client_id",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [
                        {"url": url}
                    ]
                }
            }
            response = requests.post(api_url, json=payload)
            if response.status_code == 200 and response.json().get("matches"):
                logging.warning(f"Unsafe URL detected: {url}")
                return False
            logging.info(f"URL is safe: {url}")
            return True
        except Exception as e:
            logging.error(f"Error checking URL safety: {e}")
            return False

    def start(self):
        logging.info("Starting Advanced Firewall...")
        self.monitor_traffic()
        self.manage_traffic_priority()
        Thread(target=self.update_rules, daemon=True).start()

if __name__ == "__main__":
    firewall = AdvancedFirewall()
    firewall.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping firewall...")
