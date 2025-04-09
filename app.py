from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from datetime import datetime, timedelta
import io
import sqlite3
import os
import random
import bleach
from functools import wraps

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'txt'}
app.secret_key = 'supersecretkey'


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

otp_store = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'police_id' not in session:
                return redirect('/login')
            role = session.get('role')
            if role not in required_roles:
                return "Access Denied: You do not have permission to view this page."
            return f(*args, **kwargs)
        return wrapped
    return decorator

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   police_id TEXT UNIQUE NOT NULL,
                   password TEXT NOT NULL,
                   role TEXT NOT NULL DEFAULT 'officer'
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS cases (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               title TEXT NOT NULL,
               description TEXT,
               officer TEXT,
               date_time TEXT
            )''')

    c.execute('''CREATE TABLE IF NOT EXISTS evidence (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               case_id INTEGER,
               description TEXT,
               file_path TEXT,
               uploaded_by TEXT,
               uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
               is_severe INTEGER DEFAULT 0,
               salt TEXT,
               FOREIGN KEY (case_id) REFERENCES cases(id)
            )''')

    conn.commit()
    conn.close()

init_db()

def send_otp_to_console(police_id, otp):
    if app.debug:
        print(f"\n📲 OTP for '{police_id}': {otp} (valid for 5 minutes)\n")

@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        police_id = request.form['police_id']
        password = generate_password_hash(request.form['password'])
        role = request.form.get('role', 'officer')

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (police_id, password, role) VALUES (?, ?, ?)", (police_id, password, role))
            conn.commit()
            conn.close()
            return redirect('/login')
        except:
            return "Police ID already exists."
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        police_id = request.form['police_id']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT password, role FROM users WHERE police_id = ?", (police_id,))
        result = c.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            otp = str(random.randint(100000, 999999))
            otp_store[police_id] = {'otp': otp, 'expires': datetime.now() + timedelta(minutes=5)}
            send_otp_to_console(police_id, otp)
            session['temp_police_id'] = police_id
            session['temp_role'] = result[1]
            return redirect('/verify_otp')
        else:
            return "Invalid credentials."
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    police_id = session.get('temp_police_id')
    if not police_id:
        return redirect('/login')

    if request.method == 'POST':
        entered_otp = request.form['otp']
        record = otp_store.get(police_id)

        if record and record['otp'] == entered_otp and datetime.now() < record['expires']:
            session['police_id'] = police_id
            session['role'] = session.get('temp_role')
            session.pop('temp_police_id', None)
            session.pop('temp_role', None)
            otp_store.pop(police_id, None)
            return redirect('/dashboard')
        else:
            return "Invalid or expired OTP."
    return render_template('verify_otp.html')

@app.route('/dashboard')
def dashboard():
    if 'police_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', role=session.get('role'))

@app.route('/add_case', methods=['GET', 'POST'])
@role_required(['officer', 'admin'])
def add_case():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        officer = session['police_id']
        date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO cases (title, description, officer, date_time) VALUES (?, ?, ?, ?)",
                  (title, description, officer, date_time))
        conn.commit()
        conn.close()
        return "Case added successfully! <br><a href='/dashboard'>Back to Dashboard</a>"

    return render_template('add_case.html')

@app.route('/view_cases')
@role_required(['officer', 'admin', 'writer', 'constable'])
def view_cases():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM cases")
    cases = c.fetchall()
    conn.close()
    return render_template('view_cases.html', cases=cases)

@app.route('/case/<int:case_id>')
@role_required(['officer', 'admin', 'writer', 'constable'])
def view_case_detail(case_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT title, description, officer FROM cases WHERE id = ?", (case_id,))
    case = c.fetchone()
    conn.close()

    if case:
        return render_template('case_detail.html', case=case)
    else:
        return "Case not found"

@app.route('/upload_evidence', methods=['GET', 'POST'])
@role_required(['admin'])
def upload_evidence():
    if request.method == 'POST':
        case_id = request.form['case_id']
        description = request.form['description']
        file = request.files['file']
        is_severe = 1 if request.form.get('severity') == 'severe' else 0

        if not file or not allowed_file(file.filename):
            return "Invalid file type."

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_bytes = file.read()

        salt = None
        if is_severe:
            password = request.form['password']
            salt = get_random_bytes(16)
            key = PBKDF2(password, salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

            encrypted_data = cipher.nonce + tag + ciphertext
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
            salt_to_store = salt.hex()
        else:
            with open(filepath, 'wb') as f:
                f.write(file_bytes)
            salt_to_store = None

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO evidence (case_id, description, file_path, uploaded_by, is_severe, salt) VALUES (?, ?, ?, ?, ?, ?)",
                  (case_id, description, filepath, session['police_id'], is_severe, salt_to_store))
        conn.commit()
        conn.close()

        return "Evidence uploaded successfully!<br><a href='/dashboard'>Back to Dashboard</a>"

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM cases")
    cases = c.fetchall()
    conn.close()
    return render_template('upload_evidence.html', cases=cases)

@app.route('/download_evidence')
@role_required(['admin'])
def download_evidence():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, case_id, 
               (SELECT title FROM cases WHERE cases.id = evidence.case_id),
               is_severe
        FROM evidence
    """)
    evidence_list = c.fetchall()
    conn.close()
    return render_template('download_evidence.html', evidence_list=evidence_list)


@app.route('/download_evidence/<int:evidence_id>', methods=['GET', 'POST'])
@role_required(['admin'])
def download_individual_evidence(evidence_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT file_path, is_severe, salt FROM evidence WHERE id = ?", (evidence_id,))
    record = c.fetchone()
    conn.close()

    if not record:
        return "Evidence not found."

    file_path, is_severe, salt_hex = record

    if request.method == 'GET':
        # ✅ First visit: show prompt if severe, else download
        if is_severe:
            return render_template('password_prompt.html', is_severe=True, evidence_id=evidence_id)
        else:
            return send_file(file_path, as_attachment=True)

    elif request.method == 'POST':
        # ✅ After submitting password
        if is_severe:
            password = request.form['password']
            salt = bytes.fromhex(salt_hex)
            key = PBKDF2(password, salt, dkLen=32, count=100000)

            with open(file_path, 'rb') as f:
                data = f.read()

            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]

            try:
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

                return send_file(
                    io.BytesIO(decrypted_data),
                    download_name=os.path.basename(file_path),
                    as_attachment=True
                )
            except Exception:
                return render_template('password_prompt.html', is_severe=True, evidence_id=evidence_id, error="Incorrect password or decryption failed.")

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
