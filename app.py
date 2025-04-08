from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from datetime import datetime, timedelta
import sqlite3
import os
import random
from functools import wraps
from flask_mail import Mail, Message

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'txt'}

app.secret_key = 'supersecretkey'

# Mail Configuration for Mailtrap
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '32f8c816bdea0b'
app.config['MAIL_PASSWORD'] = '881d845b90134e'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@policeops.local'

mail = Mail(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

otp_store = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------- RBAC Middleware -----------------

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

# ----------------- Database Setup -----------------

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
                   FOREIGN KEY (case_id) REFERENCES cases(id)
                )''')

    conn.commit()
    conn.close()

init_db()

# ----------------- MFA Utilities -----------------

def send_otp_email(police_id, otp):
    email = f"{police_id}@example.com"  # In production, replace with real email field
    msg = Message("Your OTP Code for PoliceOps", recipients=[email])
    msg.body = f"Hello {police_id},\n\nYour OTP is: {otp}\n\nIt will expire in 5 minutes."
    mail.send(msg)

# ----------------- Routes -----------------

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
            otp = random.randint(100000, 999999)
            otp_store[police_id] = {'otp': str(otp), 'expires': datetime.now() + timedelta(minutes=5)}
            send_otp_email(police_id, otp)
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
@role_required(['officer', 'admin'])
def upload_evidence():
    if request.method == 'POST':
        case_id = request.form['case_id']
        description = request.form['description']
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO evidence (case_id, description, file_path, uploaded_by) VALUES (?, ?, ?, ?)",
                      (case_id, description, filepath, session['police_id']))
            conn.commit()
            conn.close()

            return "Evidence uploaded successfully!<br><a href='/dashboard'>Back to Dashboard</a>"
        else:
            return "Invalid file type."

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM cases")
    cases = c.fetchall()
    conn.close()
    return render_template('upload_evidence.html', cases=cases)

@app.route('/download_evidence')
@role_required(['admin', 'officer', 'constable'])
def download_evidence():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT evidence.id, evidence.file_path, evidence.case_id, cases.title
        FROM evidence
        JOIN cases ON evidence.case_id = cases.id
    ''')
    evidence_list = c.fetchall()
    conn.close()

    evidence_list = [(e[0], os.path.basename(e[1]), e[2], e[3]) for e in evidence_list]
    return render_template('download_evidence.html', evidence_list=evidence_list)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
