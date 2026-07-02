# Security Audit Project - Phase 4

This repository contains a full security audit demonstration project. It is structured around an internal staging portal web application built in Python using Flask. The application initially exposes several typical OWASP Top 10 vulnerabilities, which are then audited, documented, mitigated in a secured code branch, and verified using an automated exploit integration test suite.

---

## Repository Structure

```text
task4/
│
├── vulnerable_app/              # Original codebase with vulnerabilities
│   ├── app.py                   # Main application script
│   └── templates/               # Unsafe HTML templates (XSS and SQLi entries)
│
├── secure_app/                  # Remediated & hardened codebase
│   ├── app.py                   # Secure application script
│   └── templates/               # Escaped and sanitized HTML templates
│
├── tests/                       # Test suites
│   ├── __init__.py              # Python package initialization
│   └── exploit_tests.py         # Automated exploit integration tests
│
├── README.md                    # Instructions & overview (this file)
└── SECURITY_AUDIT.md            # Detailed White-box Security Audit Report
```

---

## Vulnerabilities Audited & Remediated

A detailed breakdown of all vulnerabilities is available in the [SECURITY_AUDIT.md](SECURITY_AUDIT.md) file. The audit covers:

1. **Remote Code Execution (RCE) via Command Injection (Critical)**
   * Input processed directly inside shell command (`shell=True`).
   * Remediated using strict RegEx hostname validation and list arguments with `shell=False`.
2. **SQL Injection - Authentication Bypass (High)**
   * User fields appended via string concatenation directly into SQL query text.
   * Remediated using parameterized queries.
3. **Insecure Direct Object Reference - IDOR (Medium)**
   * Retrieval of notes based on unsafe user-controlled ID without validating session ownership.
   * Remediated by adding authorization checks on records relative to user session IDs.
4. **Arbitrary File Read via Path Traversal (High)**
   * Server download endpoints resolving paths with relative parent directory syntax (`../`).
   * Remediated using canonical pathway check limitations and `secure_filename`.
5. **Cross-Site Scripting - Stored & Reflected (High)**
   * Bypassing automatic Jinja2 escaping using the `| safe` filter.
   * Remediated by removing the `| safe` keyword to trigger default auto-escaping.
6. **Sensitive Data Exposure (High)**
   * Database table storing passwords in plain text.
   * Remediated using PBKDF2/Scrypt hash algorithms.

---

## Installation & Setup

### Prerequisites
* Python 3.11.x or higher
* Pip (Python Package Manager)

### Install Dependencies
Install Flask and its required runtime components:
```bash
pip install Flask werkzeug requests
```

---

## Staging Test Credentials

Use the following user profiles to log in and test horizontal/vertical privilege escalation (IDOR) behavior:

| Username | Password | Role | Expected Privileges |
| :--- | :--- | :--- | :--- |
| **admin** | `admin123` | Administrator | Full access to Admin Notes (ID: 1) |
| **alice** | `alicepassword` | Standard User | Access to Alice Notes (ID: 2) |
| **bob** | `bobpassword` | Standard User | Access to Bob Notes (ID: 3) |

In the **Vulnerable Portal**, any logged-in user can access other notes (e.g., logging in as Alice and visiting `/view_note?id=1` bypasses authorization). In the **Secure Portal**, access is restricted, returning a styled `403 Forbidden` error page.

---

## How to Run & Test

### 1. Launching the Applications

* **To run the Vulnerable Application (Port 5000)**:
  ```bash
  python vulnerable_app/app.py
  ```
  Access the web page at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

* **To run the Secure Application (Port 5001)**:
  ```bash
  python secure_app/app.py
  ```
  Access the web page at: [http://127.0.0.1:5001](http://127.0.0.1:5001)

### 2. Running Automated Exploit Verification Tests

The test suite runs exploits against both portals. It verifies that exploits succeed on port 5000 (vulnerable) and are blocked on port 5001 (secure).

1. Start both servers in separate terminals (or in the background).
2. Run the testing command from the root of the workspace:
   ```bash
   python -m unittest tests.exploit_tests
   ```

All 12 checks should succeed, demonstrating successful remediation.
