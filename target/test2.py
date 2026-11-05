from flask import Flask, request, jsonify
import sqlite3
import subprocess
import pickle
import os

app = Flask(__name__)

DB = "app.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return "Welcome to Vulnerable App"

# -----------------------------
# SQL Injection
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    print("Executing:", query)

    try:
        c.execute(query)
        result = c.fetchone()
    except Exception as e:
        return str(e)

    conn.close()

    if result:
        return "Login successful"
    return "Invalid credentials"

# -----------------------------
# Command Injection
# -----------------------------
@app.route('/ping')
def ping():
    host = request.args.get('host')

    try:
        output = subprocess.check_output("ping -c 1 " + host, shell=True)
        return output.decode()
    except Exception as e:
        return str(e)

# -----------------------------
# Insecure Deserialization
# -----------------------------
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.data

    try:
        obj = pickle.loads(data)
        return f"Object: {obj}"
    except Exception as e:
        return str(e)

# -----------------------------
# File Read Vulnerability
# -----------------------------
@app.route('/read')
def read_file():
    filename = request.args.get('file')

    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return str(e)

# -----------------------------
# Debug Endpoint
# -----------------------------
@app.route('/debug')
def debug():
    return jsonify({
        "env": dict(os.environ),
        "cwd": os.getcwd()
    })

# -----------------------------
# Weak Auth Simulation
# -----------------------------
@app.route('/admin')
def admin():
    token = request.args.get('token')

    if token == "1234":
        return "Welcome admin"
    return "Unauthorized"

# -----------------------------
# Run App
# -----------------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
