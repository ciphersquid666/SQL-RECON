# SQLiScanner 🛡️

**SQLiScanner** is a powerful tool designed to identify SQL Injection vulnerabilities in web applications. It uses a set of predefined payloads to check if a website is susceptible to SQL injections, generating a report with detected vulnerabilities.

> **Disclaimer**: This tool should only be used for ethical penetration testing on systems you have explicit permission to test. Unauthorized use of this tool is illegal and unethical. ⚠️

---

## 🚀 Features

- **SQL Injection Testing**: Automatically tests for common SQL injection vulnerabilities.
- **Multi-threaded**: Run tests concurrently with multiple threads to speed up the scanning process.
- **Payload Customization**: Use custom payloads or load a custom wordlist to perform the test.
- **Report Generation**: Outputs detailed vulnerability reports in JSON format.
- **Colored Output**: Easy-to-read output with color-coding for quick results.

---

## 📜 Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/ciphersquid666/SQL-RECON.git
    ```

2. Navigate into the project folder:
    ```bash
    cd SQL-RECON
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## ⚙️ Usage

1. Run the script:
    ```bash
    python sql_scanner.py
    ```

2. Enter the target URL (e.g., `http://example.com/search`):
    ```bash
    Enter the target URL (e.g., http://example.com/search): 
    ```

3. Specify the parameter you want to test (e.g., `query`):
    ```bash
    Enter the target parameter (e.g., query): 
    ```

4. Choose whether to load a custom wordlist or use the default payloads.
5. Specify the number of threads for testing (default is 5).

---

## 📝 Example Output

```bash
Testing payload: ' OR '1'='1
[!] Vulnerability found with payload: ' OR '1'='1
[!] Vulnerable URL: http://example.com/search?query=' OR '1'='1
[+] Report generated: vulnerabilities_report.json