from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
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
                   officer TEXT
                )''')

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
    print("DEBUG: Request method is", request.method)

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        officer = session['police_id']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO cases (title, description, officer) VALUES (?, ?, ?)", 
                  (title, description, officer))
        conn.commit()
        conn.close()
        return "Case added successfully! <br><a href='/dashboard'>Back to Dashboard</a>"
    
    return render_template('add_case.html')


@app.route('/view_cases')
def view_cases():
    return render_template('view_cases.html')

@app.route('/upload_evidence')
def upload_evidence():
    return render_template('upload_evidence.html')

@app.route('/download_evidence')
def download_evidence():
    return render_template('download_evidence.html')

@app.route('/logout')
def logout():
    session.pop('police_id', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
