from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from datetime import datetime
import sqlite3
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'evidence_files'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'txt'}
UPLOAD_FOLDER = 'uploads'  # same folder used in upload_evidence
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app.secret_key = 'supersecretkey'

# --- DB SETUP ---
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   police_id TEXT UNIQUE NOT NULL,
                   password TEXT NOT NULL
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
                   uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    case_id INTEGER NOT NULL,
    uploaded_by TEXT,
    upload_time TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id)
)
''')


    conn.commit()
    conn.close()

init_db()

# --- ROUTES ---
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        police_id = request.form['police_id']
        password = generate_password_hash(request.form['password'])
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (police_id, password) VALUES (?, ?)", (police_id, password))
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
        c.execute("SELECT password FROM users WHERE police_id = ?", (police_id,))
        result = c.fetchone()
        conn.close()
        if result and check_password_hash(result[0], password):
            session['police_id'] = police_id
            return redirect('/dashboard')
        else:
            return "Invalid credentials."
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'police_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/add_case', methods=['GET', 'POST'])
def add_case():
    if 'police_id' not in session:
        return redirect('/login')

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
def view_cases():
    if 'police_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM cases")
    cases = c.fetchall()
    conn.close()

    return render_template('view_cases.html', cases=cases)

@app.route('/case/<int:case_id>')
def view_case_detail(case_id):
    if 'police_id' not in session:
        return redirect('/login')

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
def upload_evidence():
    if 'police_id' not in session:
        return redirect('/login')

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

    # Fetch all case IDs for dropdown
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM cases")
    cases = c.fetchall()
    conn.close()
    return render_template('upload_evidence.html', cases=cases)

@app.route('/download_evidence')
def download_evidence():
    if 'police_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT evidence.id, evidence.file_path, evidence.case_id, cases.title
        FROM evidence
        JOIN cases ON evidence.case_id = cases.id
    ''')
    evidence_list = c.fetchall()
    conn.close()

    # Extract just the filename from file_path for download link
    evidence_list = [(e[0], os.path.basename(e[1]), e[2], e[3]) for e in evidence_list]

    return render_template('download_evidence.html', evidence_list=evidence_list)



@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.pop('police_id', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
