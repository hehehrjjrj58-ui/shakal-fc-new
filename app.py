import os, sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "shakal.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SHAKAL_SECRET", "change-this-secret-before-public-hosting")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','player')),
      player_name TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      opponent TEXT NOT NULL, match_date TEXT DEFAULT '', result TEXT DEFAULT '', note TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS news (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL, body TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS roster (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, number TEXT DEFAULT '', position TEXT DEFAULT ''
    );
    """)
    conn.commit()
    conn.close()

def logged_in(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_only(f):
    @wraps(f)
    @logged_in
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("ئەم بەشە تایبەتە بە بەڕێوەبەر.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

@app.route("/setup", methods=["GET","POST"])
def setup():
    if db().execute("SELECT COUNT(*) n FROM users WHERE role='admin'").fetchone()["n"]:
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        confirm = request.form.get("confirm","")
        if not username or len(password) < 8:
            flash("ناوی بەکارهێنەر بنووسە و وشەی نهێنی لانیکەم ٨ پیت بێت.")
        elif password != confirm:
            flash("وشەی نهێنییەکان وەک یەک نین.")
        else:
            db().execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                         (username, generate_password_hash(password), "admin"))
            db().commit()
            flash("هەژماری بەڕێوەبەر دروست کرا. ئێستا بچۆ ژوورەوە.")
            return redirect(url_for("login"))
    return render_template("setup.html")

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["uid"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["player_name"] = user["player_name"]
            return redirect(url_for("dashboard"))
        flash("ناوی بەکارهێنەر یان وشەی نهێنی هەڵەیە.")
    return render_template("login.html")

@app.route("/dashboard")
@logged_in
def dashboard():
    matches = db().execute("SELECT * FROM matches ORDER BY id DESC").fetchall()
    news = db().execute("SELECT * FROM news ORDER BY id DESC").fetchall()
    roster = db().execute("SELECT * FROM roster ORDER BY CAST(number AS INTEGER)").fetchall()
    return render_template("dashboard.html", matches=matches, news=news, roster=roster)

@app.route("/admin/match", methods=["POST"])
@admin_only
def add_match():
    db().execute("INSERT INTO matches(opponent,match_date,result,note) VALUES(?,?,?,?)",
        (request.form["opponent"].strip(), request.form.get("match_date",""),
         request.form.get("result",""), request.form.get("note","")))
    db().commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/news", methods=["POST"])
@admin_only
def add_news():
    db().execute("INSERT INTO news(title,body) VALUES(?,?)",
        (request.form["title"].strip(), request.form["body"].strip()))
    db().commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/player", methods=["POST"])
@admin_only
def add_player():
    name=request.form["name"].strip()
    number=request.form.get("number","").strip()
    position=request.form.get("position","").strip()
    username=request.form["username"].strip()
    password=request.form["password"]
    if len(password) < 8:
        flash("وشەی نهێنیی یاریزان دەبێت لانیکەم ٨ پیت بێت.")
    else:
        try:
            db().execute("INSERT INTO roster(name,number,position) VALUES(?,?,?)",(name,number,position))
            db().execute("INSERT INTO users(username,password_hash,role,player_name) VALUES(?,?,?,?)",
                         (username,generate_password_hash(password),"player",name))
            db().commit()
            flash("یاریزان و هەژمارەکەی زیاد کران.")
        except sqlite3.IntegrityError:
            db().rollback()
            flash("ئەم ناوی بەکارهێنەرە پێشتر بەکارهاتووە.")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return "SHAKAL FC OK"

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

def db_admin_missing():
    conn=sqlite3.connect(DB_PATH)
    try:
        return conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] == 0
    finally:
        conn.close()
