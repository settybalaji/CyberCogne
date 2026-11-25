"""Fixed version of the demo app: parameterized queries, output escaping, security headers."""
import sqlite3
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
INSERT INTO users(username,password,role) VALUES('admin','S3cret!pass','admin'),('alice','alice123','user');
""")  # NOTE: real apps must store salted password hashes (bcrypt/argon2), not plain text.

@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    return r

@app.route("/")
def index():
    return "<h2>Demo Shop (SECURE)</h2>"

@app.route("/login", methods=["POST"])
def login():
    row = db.execute("SELECT username, role FROM users WHERE username=? AND password=?",
                     (request.form.get("username", ""), request.form.get("password", ""))).fetchone()
    return (f"Welcome {escape(row[0])}", 200) if row else ("Invalid credentials", 401)

@app.route("/search")
def search():
    return f"<h3>Results for: {escape(request.args.get('q', ''))}</h3>"

if __name__ == "__main__":
    app.run("127.0.0.1", 5001)
