import os
import re
import sqlite3
import subprocess
from flask import Flask, request, render_template, redirect, url_for, session, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Mitigation: Read secret key from environment or use a secure fallback. Do not hardcode a development key.
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

DB_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), 'secure.db'))
ALLOWED_DOWNLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS notes')
    cursor.execute('DROP TABLE IF EXISTS feedback')
    
    # Mitigation: Storing cryptographically secure password hashes rather than plaintext
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            message TEXT
        )
    ''')
    
    # Generate secure password hashes
    admin_pw = generate_password_hash('admin123')
    alice_pw = generate_password_hash('alicepassword')
    bob_pw = generate_password_hash('bobpassword')
    
    # Insert users
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', admin_pw, 'admin'))
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('alice', alice_pw, 'user'))
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('bob', bob_pw, 'user'))
    
    # Insert notes
    cursor.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (1, 'Secret admin notes: Server backup is at C:\\backup\\'))
    cursor.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (2, 'Alice personal diary entry 1'))
    cursor.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (3, 'Bob shopping list: apples, milk'))
    
    conn.commit()
    conn.close()

# Initialize DB if not exists
if not os.path.exists(DB_FILE):
    init_db()

# Mitigation: Implement security headers globally
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    # Server headers are stripped or hidden where possible
    response.headers.pop('Server', None)
    return response

@app.route('/')
def index():
    return render_template('index.html')

# Mitigation: Parameterized SQL Query & Secure Passwords
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Mitigation: Use SQL query parameterization to block SQL Injection
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            # Mitigation: Check password against cryptographic hash, preventing plain-text lookup
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid credentials"
        except Exception as e:
            # Mitigation: Avoid disclosing internal database structure in error messages
            error = "An error occurred during authentication."
        finally:
            conn.close()
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# Mitigation: Secure Command execution using input validation & safe arguments (shell=False)
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    output = ""
    target = ""
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        
        # Mitigation: Enforce strict input validation using regular expression (allow only valid hostname/IP)
        # Bypasses characters like &, |, ;, $, ` which are used for injection
        if re.match(r"^[a-zA-Z0-9.-]+$", target):
            # Mitigation: Execute subprocess without shell=True, passing inputs as lists to prevent RCE
            cmd = ["ping", "-n", "1", target]
            try:
                # Limit execution time to prevent Denial of Service (DoS) using timeout
                result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5, check=True)
                output = result.stdout
            except subprocess.TimeoutExpired:
                output = "Ping request timed out."
            except subprocess.CalledProcessError as e:
                output = e.stdout if e.stdout else "Host unreachable or error code returned."
            except Exception as e:
                output = "Execution failed."
        else:
            output = "Invalid input target. Only standard IP addresses or domain names are allowed."
            
    return render_template('ping.html', output=output, target=target)

# Mitigation: Fix IDOR by validating user ownership of resources
@app.route('/view_note')
def view_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    note_id = request.args.get('id')
    if not note_id or not note_id.isdigit():
        return "Invalid parameters", 400
        
    user_id = session['user_id']
    role = session['role']
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Mitigation: Include current user ID in the query constraints OR check roles,
    # preventing horizontal or vertical privilege escalation (IDOR)
    if role == 'admin':
        cursor.execute("""
            SELECT notes.content, users.username 
            FROM notes 
            JOIN users ON notes.user_id = users.id 
            WHERE notes.id = ?
        """, (note_id,))
    else:
        cursor.execute("""
            SELECT notes.content, users.username 
            FROM notes 
            JOIN users ON notes.user_id = users.id 
            WHERE notes.id = ? AND notes.user_id = ?
        """, (note_id, user_id))
        
    note = cursor.fetchone()
    conn.close()
    
    if note:
        return render_template('note.html', content=note[0], owner=note[1], id=note_id)
    else:
        # Mitigation: Return generic message and unauthorized status code
        return "Access denied or note not found", 403

# Mitigation: Secure Path Traversal using safe directory confinement and secure names
@app.route('/download')
def download():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    filename = request.args.get('file', '')
    if not filename:
        return "Filename parameter is missing", 400
        
    # Mitigation 1: Strip relative paths using secure_filename
    cleaned_filename = secure_filename(filename)
    if not cleaned_filename:
        return "Invalid filename", 400
        
    # Mitigation 2: Ensure canonical resolved path is restricted strictly to ALLOWED_DOWNLOAD_DIR
    filepath = os.path.abspath(os.path.join(ALLOWED_DOWNLOAD_DIR, cleaned_filename))
    
    if not filepath.startswith(ALLOWED_DOWNLOAD_DIR + os.sep) and filepath != ALLOWED_DOWNLOAD_DIR:
        return "Access to specified file path is forbidden.", 403
        
    try:
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return "Requested file not found", 404

# Mitigation: Stored and Reflected XSS fixes via removal of unsafe/safe filters
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    if request.method == 'POST':
        # Simple mitigation: Strip HTML tags from input or let Jinja2 escape it (Jinja2 autoescape will handle)
        name = request.form.get('name', '').strip()
        message = request.form.get('message', '').strip()
        
        # Enforce character length validation
        if len(name) > 50 or len(message) > 500:
            return "Input exceeds max length limits", 400
            
        cursor.execute("INSERT INTO feedback (name, message) VALUES (?, ?)", (name, message))
        conn.commit()

    cursor.execute("SELECT name, message FROM feedback ORDER BY id DESC")
    feedbacks = cursor.fetchall()
    conn.close()

    # Reflected query parameter - handled securely in templates
    reflected_msg = request.args.get('msg', '').strip()
    
    return render_template('feedback.html', feedbacks=feedbacks, reflected_msg=reflected_msg)

if __name__ == '__main__':
    # Initialize some dummy static file for download verification
    os.makedirs(ALLOWED_DOWNLOAD_DIR, exist_ok=True)
    with open(os.path.join(ALLOWED_DOWNLOAD_DIR, 'sample.txt'), 'w') as f:
        f.write("This is a safe sample static file for download.")
        
    # Mitigation: Disable Flask debug mode in staging/production setups to avoid RCE or console exposure
    app.run(host='127.0.0.1', port=5001, debug=False)
