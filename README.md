# Security Audit & Hardening Project (Phase 4)

[![Security Status](https://img.shields.io/badge/Security-Audited%20%26%20Hardened-brightgreen.svg)](#)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-black.svg)](#)

This repository contains a comprehensive security audit demonstration project. It is structured around an internal staging portal web application built in Python using Flask. The application initially exposes several typical OWASP Top 10 vulnerabilities, which are then audited, documented, mitigated in a secured code branch, and verified using an automated exploit integration test suite.

---

## 📁 Repository Structure

```text
task4/
│
├── vulnerable_app/              # Original codebase with vulnerabilities
│   ├── app.py                   # Main application script (Port 5000)
│   ├── static/                  # Shared text files and assets
│   └── templates/               # Unsafe HTML templates (Crimson Red Theme)
│
├── secure_app/                  # Remediated & hardened codebase
│   ├── app.py                   # Secure application script (Port 5001)
│   ├── static/                  # Shared text files and assets
│   └── templates/               # Escaped templates (Cosmic Multi-color Sidebar Theme)
│
├── tests/                       # Test suites
│   ├── __init__.py              # Python package initialization
│   └── exploit_tests.py         # Automated exploit integration tests
│
├── README.md                    # Instructions & overview (this file)
└── SECURITY_AUDIT.md            # Detailed White-box Security Audit Report
```

---

## 🛡️ Vulnerabilities Audited & Remediated

A detailed breakdown of all vulnerabilities is available in the [SECURITY_AUDIT.md](SECURITY_AUDIT.md) file. The audit covers:

1. **Remote Code Execution (RCE) via Command Injection (Critical)**
   * **Vulnerability:** Input processed directly inside shell command (`shell=True`).
   * **Remediation:** Strict RegEx validation against target domain/IP pattern and command list execution with `shell=False`.
2. **SQL Injection - Authentication Bypass (High)**
   * **Vulnerability:** User fields appended via string concatenation directly into SQL query text.
   * **Remediation:** Enforced parameterized query bindings.
3. **Insecure Direct Object Reference - IDOR (Medium)**
   * **Vulnerability:** Retrieval of notes based on user-controlled ID parameter without session ownership checks.
   * **Remediation:** Session user ID validation against note owner field.
4. **Arbitrary File Read via Path Traversal (High)**
   * **Vulnerability:** Download endpoints resolving paths with relative parent directory syntax (`../`).
   * **Remediation:** Strict path canonicalization, `secure_filename` checks, and boundary directory locking.
5. **Cross-Site Scripting (XSS) - Stored & Reflected (High)**
   * **Vulnerability:** Auto-escaping disabled on templates using the `| safe` filter.
   * **Remediation:** Removed the `| safe` keyword to restore context-aware Jinja2 auto-escaping.
6. **Sensitive Data Exposure (High)**
   * **Vulnerability:** Databases storing passwords in plain text.
   * **Remediation:** Enforced cryptographic PBKDF2 password hashing.

---

## 🔐 Staging Test Credentials

Use these profiles to test horizontal/vertical privilege escalation (IDOR) behavior:

| Username | Password | Role | Expected Privileges |
| :--- | :--- | :--- | :--- |
| **admin** | `admin123` | Administrator | Full access to Admin Notes (ID: 1) |
| **alice** | `alicepassword` | Standard User | Access to Alice Notes (ID: 2) |
| **bob** | `bobpassword` | Standard User | Access to Bob Notes (ID: 3) |

* **Vulnerable Portal:** Any logged-in user can access other notes (e.g., logging in as Alice and visiting `/view_note?id=1` bypasses authorization).
* **Secure Portal:** Restricted access; unauthorized note requests trigger a custom `403 Forbidden` error page.

---

## 🚀 Installation & Setup

### 1. Clone & Navigate to Repository
```bash
git clone https://github.com/Aathi123-123/Security-Audit-Project_4.git
cd Security-Audit-Project_4
```

### 2. Install Dependencies
Ensure you have Python 3.11+ installed. Run:
```bash
pip install Flask werkzeug requests
```

---

## 💻 How to Run & Verify

### Step 1: Start both portals in separate terminal sessions

* **To run the Vulnerable Application (Port 5000)**:
  ```bash
  python vulnerable_app/app.py
  ```
  Access the web page at: [http://127.0.0.1:5000](http://127.0.0.1:5000) (Styled in **Crimson Red** to signify danger).

* **To run the Secure Application (Port 5001)**:
  ```bash
  python secure_app/app.py
  ```
  Access the web page at: [http://127.0.0.1:5001](http://127.0.0.1:5001) (Styled in a **Futuristic Cosmic Multi-color Gradient** with Sidebar Navigation).

---

### Step 2: Automated exploit verification tests

The test suite runs exploits against both portals. It verifies that exploits succeed on port 5000 (vulnerable) and are blocked on port 5001 (secure).

From the root of the workspace, run:
```bash
python -m unittest tests.exploit_tests
```
**Expected Output:**
```text
............
----------------------------------------------------------------------
Ran 12 tests in 0.704s

OK
```

---

### Step 3: Manual reproduction examples

#### 1. SQL Injection Bypass
* **Target:** Login portal (`/login`)
* **Payload:** Username: `' OR '1'='1` | Password: (anything)
* **Vulnerable App:** Logs you in directly as the first user in the database (`admin`).
* **Secure App:** Displays "Invalid Credentials" and blocks entry.

#### 2. Command Injection (RCE)
* **Target:** Host diagnostic field (`/ping`)
* **Payload:** `127.0.0.1; whoami` (Linux/Mac) or `127.0.0.1 & whoami` (Windows)
* **Vulnerable App:** Executes the command injection and appends system command outputs to the webpage.
* **Secure App:** Rejects command injection attempt immediately with a validation error.

#### 3. Path Traversal
* **Target:** File download tool (`/download?file=...`)
* **Payload:** `/download?file=../vulnerable.db` (Vulnerable App) or `/download?file=../secure.db` (Secure App)
* **Vulnerable App:** Downloads the raw database files.
* **Secure App:** Blocks the request and returns a custom `404 Not Found` page.
