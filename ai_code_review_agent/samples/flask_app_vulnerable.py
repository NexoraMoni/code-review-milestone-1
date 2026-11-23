"""Sample 2 (medium): intentionally vulnerable Flask app for demo/testing."""
import hashlib
import os
import pickle
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PASSWORD = "SuperSecret123"
API_KEY = "sk_live_abcdef123456"


def login(username, password):
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    row = conn.execute(query).fetchone()
    if row and row[2] == password:
        return True
    return False


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/admin/delete/<uid>", methods=["POST"])
def delete_user(uid):
    conn = sqlite3.connect("app.db")
    conn.execute("DELETE FROM users WHERE id = " + uid)
    return "deleted"


@app.route("/load", methods=["POST"])
def load():
    data = pickle.loads(request.data)
    return str(data)


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def risky():
    try:
        return 1 / 0
    except:
        pass


if __name__ == "__main__":
    app.run(debug=True)
