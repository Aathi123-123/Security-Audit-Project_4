import os
import sqlite3
import subprocess
from flask import Flask, request, render_template, redirect, url_for, session, send_file

app = Flask(__name__)
app.secret_key = "super_secret_dev_key_do_not_use_in_production_12345" # Sensitive Data Exposure / Hardcoded Secret

# Initialize Database with vulnerable schema
DB_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), 'vulnerable.db'))

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS notes')
    # Vulnerability: Storing plain text passwords (Sensitive Data Exposure)
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
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
    # Insert default users
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'alicepassword', 'user')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('bob', 'bobpassword', 'user')")
    
    # Insert notes
    cursor.execute("INSERT INTO notes (user_id, content) VALUES (1, 'Secret admin notes: Server backup is at C:\\backup\\')")
    cursor.execute("INSERT INTO notes (user_id, content) VALUES (2, 'Alice personal diary entry 1')")
    cursor.execute("INSERT INTO notes (user_id, content) VALUES (3, 'Bob shopping list: apples, milk')")
    
    conn.commit()
    conn.close()

# Initialize DB if not exists
if not os.path.exists(DB_FILE):
    init_db()

@app.route('/')
def index():
    return render_template('index.html')

# SQL Injection Vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerability: Dynamic SQL Query Construction without parameterization
        # e.g., Entering admin' OR '1'='1 for username will bypass authentication
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid credentials"
        except Exception as e:
            error = f"Database Error: {str(e)}"
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

# Command Injection Vulnerability
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    output = ""
    target = ""
    if request.method == 'POST':
        target = request.form.get('target', '')
        # Vulnerability: Direct execution of shell command using user input with shell=True
        # e.g. target = '127.0.0.1 && dir' or '127.0.0.1; cat /etc/passwd'
        cmd = f"ping -n 1 {target}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            output = str(e)
            
    return render_template('ping.html', output=output, target=target)

# Insecure Direct Object Reference (IDOR) Vulnerability
@app.route('/view_note')
def view_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    note_id = request.args.get('id')
    # Vulnerability: Fetching record strictly based on user-provided note ID without validating if it belongs to the logged-in user
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(f"SELECT notes.content, users.username FROM notes JOIN users ON notes.user_id = users.id WHERE notes.id = {note_id}")
    note = cursor.fetchone()
    conn.close()
    
    if note:
        return render_template('note.html', content=note[0], owner=note[1], id=note_id)
    return "Note not found", 404

# Path Traversal (Arbitrary File Read) Vulnerability
@app.route('/download')
def download():
    # Vulnerability: No path verification or validation. Direct file access using user input.
    # e.g. /download?file=../../../../Windows/System32/drivers/etc/hosts or /download?file=vulnerable.db
    filename = request.args.get('file', '')
    if not filename:
        return "Filename parameter is missing", 400
    
    # Path traversal payload bypasses expected static directory
    filepath = os.path.join(os.path.dirname(__file__), 'static', filename)
    try:
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return f"File access error: {str(e)}", 404

# Stored and Reflected XSS Vulnerabilities
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    # Store feedback in memory database/list for stored XSS demonstration
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create feedback table if not exists
    cursor.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, message TEXT)')
    conn.commit()

    if request.method == 'POST':
        name = request.form.get('name', '')
        message = request.form.get('message', '')
        cursor.execute("INSERT INTO feedback (name, message) VALUES (?, ?)", (name, message))
        conn.commit()

    cursor.execute("SELECT name, message FROM feedback ORDER BY id DESC")
    feedbacks = cursor.fetchall()
    conn.close()

    # Vulnerability: Reflected XSS from request arg directly rendered without escaping
    # Jinja default autoescape is bypassed if we mark it safe, or if we use raw string formatting in templates
    reflected_msg = request.args.get('msg', '')
    
    return render_template('feedback.html', feedbacks=feedbacks, reflected_msg=reflected_msg)

if __name__ == '__main__':
    # Initialize some dummy static file for download verification
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))
    os.makedirs(static_dir, exist_ok=True)
    with open(os.path.join(static_dir, 'sample.txt'), 'w') as f:
        f.write("This is a safe sample static file for download.")
        
    app.run(host='127.0.0.1', port=5000, debug=True)
