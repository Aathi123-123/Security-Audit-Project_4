# Security Audit Report: Internal Diagnostics Portal

This document details the security audit findings for the Internal Diagnostics Portal application. It outlines identified risks, documents vulnerabilities, details Proofs of Concept (PoCs), and provides implemented code remediations verified through automated integration tests.

---

## 1. Executive Summary

A comprehensive white-box security audit was performed on the staging version of the **Internal Diagnostics Portal** application. The objective of the audit was to evaluate the application's posture against common security risks, specifically focusing on the OWASP Top 10 vulnerabilities.

The initial audit identified several **Critical** and **High-risk** vulnerabilities that could lead to complete system compromise, including Remote Code Execution (RCE), arbitrary file exposure, database compromise, and unauthorized administrative access. 

All identified vulnerabilities have been systematically remediated and verified using automated test suites. The application has been hardened to prevent exploitation.

---

## 2. Engagement Scope & Methodology

The scope of this audit covers the server-side logic and front-end interface components of the web portal:
* **Target Application**: Flask-based Diagnostics Portal
* **Review Type**: Static Application Security Testing (SAST) & Dynamic Application Security Testing (DAST)
* **Standards Applied**: OWASP Top 10 (2021) Standards

### Severity Rating Matrix

We align findings according to standard CVSS v3.1 rating parameters:
* **Critical (9.0 - 10.0)**: Direct system control or remote code execution, requiring immediate patching.
* **High (7.0 - 8.9)**: Unauthorized database exposure, severe data leakage, or authorization bypass.
* **Medium (4.0 - 6.9)**: Restricted unauthorized access (e.g., IDOR on single objects) or data disclosure.
* **Low (0.1 - 3.9)**: Security header omissions or information disclosure.

---

## 3. Summary of Findings

| Vulnerability ID | Vulnerability Name | Severity | OWASP Reference | Remediation Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Remote Code Execution via Command Injection | **Critical** (9.8) | A03:2021-Injection | **Remediated** |
| **SEC-02** | SQL Injection (Authentication Bypass) | **High** (8.8) | A03:2021-Injection | **Remediated** |
| **SEC-03** | Insecure Direct Object Reference (IDOR) | **Medium** (6.5) | A01:2021-Broken Access Control | **Remediated** |
| **SEC-04** | Arbitrary File Read via Path Traversal | **High** (7.5) | A01:2021-Broken Access Control | **Remediated** |
| **SEC-05** | Reflected & Stored Cross-Site Scripting (XSS) | **High** (8.1) | A03:2021-Injection | **Remediated** |
| **SEC-06** | Sensitive Data Exposure (Plaintext Passwords) | **High** (7.5) | A02:2021-Cryptographic Failures | **Remediated** |

---

## 4. Detailed Vulnerability Findings

### SEC-01: Remote Code Execution via Command Injection
* **Severity**: **Critical** (CVSS: 9.8)
* **OWASP Rating**: **A03:2021-Injection**
* **Vulnerable Endpoint**: `/ping` (POST)
* **Vulnerable Code**: [vulnerable_app/app.py:108-118](vulnerable_app/app.py#L108-L118)

#### Description
The ping diagnostic tool processes user input (a domain or IP address) and passes it directly to a shell command (`ping -n 1 {target}`) using `subprocess.check_output(..., shell=True)`. Because `shell=True` is enabled and no input sanitization is performed, attackers can inject shell metacharacters (such as `&`, `|`, `;`) to execute arbitrary operating system commands under the context of the running web application server.

#### Proof of Concept (PoC)
An attacker can submit the following payload in the `target` parameter:
```bash
127.0.0.1 & echo EXPLOITED_RCE
```
This causes the server to execute:
```bash
ping -n 1 127.0.0.1 & echo EXPLOITED_RCE
```
This executes the ping command followed immediately by the arbitrary `echo` command, revealing remote command execution on the server.

#### Remediation
In [secure_app/app.py:133-149](secure_app/app.py#L133-L149), the vulnerability was mitigated by:
1. Validating that the host input strictly matches an IP address or alphanumeric hostname pattern using a regular expression (`^[a-zA-Z0-9.-]+$`).
2. Executing the ping command using `shell=False` and passing arguments as an array (`["ping", "-n", "1", target]`), preventing shell expansion and command injection.

```python
# Remediation Snippet
if re.match(r"^[a-zA-Z0-9.-]+$", target):
    cmd = ["ping", "-n", "1", target]
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5, check=True)
    output = result.stdout
else:
    output = "Invalid input target. Only standard IP addresses or domain names are allowed."
```

---

### SEC-02: SQL Injection (Authentication Bypass)
* **Severity**: **High** (CVSS: 8.8)
* **OWASP Rating**: **A03:2021-Injection**
* **Vulnerable Endpoint**: `/login` (POST)
* **Vulnerable Code**: [vulnerable_app/app.py:59-78](vulnerable_app/app.py#L59-L78)

#### Description
The login feature builds an SQL statement by concatenating user inputs (`username` and `password`) directly into a raw query string. An attacker can input SQL control characters to bypass authentication without knowing valid credentials.

#### Proof of Concept (PoC)
An attacker can submit the following payload in the `username` field:
```sql
admin' OR '1'='1
```
This translates to the following executed query:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '...'
```
The condition `'1'='1'` is always true, which makes the query return the first record in the database (typically the `admin` user), successfully logging the attacker in.

#### Remediation
In [secure_app/app.py:90-109](secure_app/app.py#L90-L109), the query was refactored to use SQL parameters, rendering user input as literal values rather than executable code:
```python
# Remediation Snippet
cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
user = cursor.fetchone()
if user and check_password_hash(user[2], password):
    # Log user in
```

---

### SEC-03: Insecure Direct Object Reference (IDOR)
* **Severity**: **Medium** (CVSS: 6.5)
* **OWASP Rating**: **A01:2021-Broken Access Control**
* **Vulnerable Endpoint**: `/view_note` (GET)
* **Vulnerable Code**: [vulnerable_app/app.py:121-134](vulnerable_app/app.py#L121-L134)

#### Description
The application hosts a private note viewing feature. It retrieves notes using a user-supplied query parameter `id` (e.g. `/view_note?id=1`). The application fails to check whether the note belongs to the currently logged-in user, permitting horizontal privilege escalation.

#### Proof of Concept (PoC)
If user `alice` (User ID 2) logs in and visits `/view_note?id=1` (which belongs to `admin`), the application retrieves and renders the administrator's private notes, exposing sensitive information.

#### Remediation
In [secure_app/app.py:152-181](secure_app/app.py#L152-L181), authorization checks were added. The query validates ownership by forcing the note to match both the requested note ID AND the current user's session ID (unless the user has the administrative role):
```python
# Remediation Snippet
if role == 'admin':
    cursor.execute("SELECT notes.content, users.username FROM notes JOIN users ON notes.user_id = users.id WHERE notes.id = ?", (note_id,))
else:
    cursor.execute("SELECT notes.content, users.username FROM notes JOIN users ON notes.user_id = users.id WHERE notes.id = ? AND notes.user_id = ?", (note_id, user_id))
```

---

### SEC-04: Arbitrary File Read via Path Traversal
* **Severity**: **High** (CVSS: 7.5)
* **OWASP Rating**: **A01:2021-Broken Access Control**
* **Vulnerable Endpoint**: `/download` (GET)
* **Vulnerable Code**: [vulnerable_app/app.py:137-147](vulnerable_app/app.py#L137-L147)

#### Description
The download feature permits downloading files by taking a file name parameter and appending it to the `static` directory pathway. The app does not sanitize file paths, allowing relative path indicators (`../` or `..\`) to resolve files outside of the intended directory.

#### Proof of Concept (PoC)
An attacker can view the database file containing stored users or sensitive operating system files by requesting:
```http
GET /download?file=../vulnerable.db
```
or (on Windows environments):
```http
GET /download?file=../../../../../../Windows/System32/drivers/etc/hosts
```
This forces the application to return the files as downloads.

#### Remediation
In [secure_app/app.py:184-209](secure_app/app.py#L184-L209), traversal attempts are mitigated using:
1. `secure_filename` from `werkzeug.utils` to strip directory components from the input.
2. Checking that the absolute resolved canonical path starts with the allowed `static/` directory prefix:
```python
# Remediation Snippet
cleaned_filename = secure_filename(filename)
filepath = os.path.abspath(os.path.join(ALLOWED_DOWNLOAD_DIR, cleaned_filename))

if not filepath.startswith(ALLOWED_DOWNLOAD_DIR + os.sep) and filepath != ALLOWED_DOWNLOAD_DIR:
    return "Access to specified file path is forbidden.", 403
```

---

### SEC-05: Reflected & Stored Cross-Site Scripting (XSS)
* **Severity**: **High** (CVSS: 8.1)
* **OWASP Rating**: **A03:2021-Injection**
* **Vulnerable Endpoint**: `/feedback` (GET & POST)
* **Vulnerable Templates**: [vulnerable_app/templates/feedback.html:19](vulnerable_app/templates/feedback.html#L19) and [vulnerable_app/templates/feedback.html:48-49](vulnerable_app/templates/feedback.html#L48-L49)

#### Description
Both reflected inputs (`msg` URL parameter) and stored inputs (comments submitted to the database) are rendered in the HTML response using Jinja2's `| safe` filter. This explicitly disables Flask's built-in HTML autoescaping, allowing raw Javascript payloads to execute in the victim's browser context.

#### Proof of Concept (PoC)
* **Reflected XSS**: Visiting `/feedback?msg=<script>alert('ReflectedXSS')</script>` triggers the browser alert.
* **Stored XSS**: Submitting a feedback comment with the message `<script>alert('StoredXSS')</script>` stores it in the database. Anyone loading `/feedback` will trigger the execution of the payload.

#### Remediation
In [secure_app/templates/feedback.html:19](secure_app/templates/feedback.html#L19) and [secure_app/templates/feedback.html:48-49](secure_app/templates/feedback.html#L48-L49), the `| safe` filters were removed. Jinja2 will now escape HTML brackets automatically:
```html
<!-- Remediation Snippet -->
<strong>System Notice:</strong> {{ reflected_msg }}

<!-- ... -->
<span class="feedback-name">{{ name }}</span> says:
<div class="feedback-msg">{{ message }}</div>
```

---

### SEC-06: Sensitive Data Exposure (Plaintext Passwords)
* **Severity**: **High** (CVSS: 7.5)
* **OWASP Rating**: **A02:2021-Cryptographic Failures**
* **Vulnerable Database Schema**: [vulnerable_app/app.py:12-42](vulnerable_app/app.py#L12-L42)

#### Description
The database stores user passwords in plain text. If an attacker downloads the database (e.g., via Path Traversal or SQL Injection) or gains localized server access, they can immediately compromise all user credentials.

#### Proof of Concept (PoC)
Inspecting the SQLite database shows:
```sql
SELECT id, username, password FROM users;
-- 1 | admin | admin123
-- 2 | alice | alicepassword
```
Passwords are fully readable.

#### Remediation
In [secure_app/app.py:17-54](secure_app/app.py#L17-L54), the application uses `werkzeug.security` to hash password variables using PBKDF2/Scrypt before storing them:
```python
# Remediation Snippet
admin_pw = generate_password_hash('admin123')
cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', admin_pw, 'admin'))
```
Verification checks are carried out using:
```python
check_password_hash(user[2], password)
```

---

## 5. Security Headers & Configuration Hardening

The web application's configuration was updated with several security features:
1. **Flask Debug Mode**: Disabled (`debug=False`) to avoid showing internal trace logs and debugger console tokens.
2. **HTTP Headers**: The application sets the following security headers in [secure_app/app.py:59-69](secure_app/app.py#L59-L69):
   * `Content-Security-Policy (CSP)`: Restricted loading of resources only to safe local components.
   * `X-Frame-Options: DENY`: Blocks Clickjacking attempts.
   * `X-Content-Type-Options: nosniff`: Prevents MIME-sniffing.
   * `Strict-Transport-Security (HSTS)`: Restricts browser communication to HTTPS.

---

## 6. Audit Conclusion

The application's initial configuration exposed it to critical and high-impact risks that would lead to total system compromise. By applying standard secure programming principles (query parameterization, strict regex validation, canonical path resolution, HTML autoescaping, password hashing, and security headers), all vulnerabilities have been fully mitigated.

The effectiveness of these fixes is validated by the automated test suite, which shows that all exploit payloads are blocked by the secure codebase.
