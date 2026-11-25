"""
INTENTIONALLY VULNERABLE demo app (SQLi + reflected XSS + missing headers).
Runs on 127.0.0.1 only. NEVER deploy it. Use it as a safe practice target for Burp/Nikto/the tester.
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
INSERT INTO users(username,password,role) VALUES('admin','S3cret!pass','admin'),('alice','alice123','user');
CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO products(name) VALUES('Laptop'),('Phone'),('Headphones');
""")

PAGE = "<h2>Demo Shop (VULNERABLE)</h2><form method=post action=/login>User <input name=username> Pass <input name=password type=password><button>Login</button></form><form action=/search>Search <input name=q><button>Go</button></form>"

@app.route("/")
def index():
    return PAGE

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    query = f"SELECT username, role FROM users WHERE username='{u}' AND password='{p}'"   # VULN: SQL injection
    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as e:
        return f"Database error: {e}", 500                                                    # VULN: verbose errors
    return f"Welcome {row[0]} ({row[1]})" if row else ("Invalid credentials", 401)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h3>Results for: {q}</h3>"                                                      # VULN: reflected XSS

if __name__ == "__main__":
    app.run("127.0.0.1", 5000)
