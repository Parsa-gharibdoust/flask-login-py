import os
import secrets
import time
from datetime import timedelta

import bcrypt
import click
import mysql.connector
from flask import Flask, abort, g, jsonify, redirect, request, send_from_directory, session
from mysql.connector import errorcode

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


if load_dotenv:
    load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=8 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
)

FRONT_DIR = os.path.join(app.root_path, "login-panel")
PUBLIC_FILES = {"app.js", "dashboard.js"}
MAX_BAD_LOGINS = 5
BAD_LOGIN_SECONDS = 15 * 60
bad_logins = {}

fake_hash_for_timing = bcrypt.hashpw(b"nope-nope-nope", bcrypt.gensalt())


def db_config():
    return {
        "host": os.environ.get("MYSQL_HOST", "localhost"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", "py_login"),
        "connection_timeout": 3,
    }


def get_db():
    if "db" not in g or not g.db.is_connected():
        g.db = mysql.connector.connect(**db_config())
    return g.db


@app.teardown_appcontext
def close_db(_err=None):
    db = g.pop("db", None)
    if db is not None and db.is_connected():
        db.close()


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def check_csrf():
    sent_token = request.headers.get("X-CSRF-Token", "")
    real_token = session.get("csrf_token", "")
    if not sent_token or not real_token or not secrets.compare_digest(sent_token, real_token):
        abort(400)


def clean_old_hits(key):
    now = time.monotonic()
    hits = [x for x in bad_logins.get(key, []) if now - x < BAD_LOGIN_SECONDS]
    bad_logins[key] = hits
    return hits


def too_many_wrong(username):
    key = f"{request.remote_addr or 'local'}:{username.lower()}"
    return key, len(clean_old_hits(key)) >= MAX_BAD_LOGINS


def add_wrong_try(key):
    hits = clean_old_hits(key)
    hits.append(time.monotonic())
    bad_logins[key] = hits


def password_ok(password, saved_hash):
    if isinstance(saved_hash, str):
        saved_hash = saved_hash.encode("utf-8")
    try:
        return bcrypt.checkpw(password.encode("utf-8"), saved_hash)
    except ValueError:
        return False


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


@app.get("/")
def index():
    if session.get("user_id"):
        return redirect("/dashboard")
    return send_from_directory(FRONT_DIR, "index.html")


@app.get("/assets/<path:filename>")
def assets(filename):
    if filename not in PUBLIC_FILES:
        abort(404)
    return send_from_directory(FRONT_DIR, filename)


@app.get("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect("/")
    return send_from_directory(FRONT_DIR, "dashboard.html")


@app.get("/api/csrf")
def get_csrf():
    return jsonify({"csrfToken": csrf_token()})


@app.post("/api/login")
def login():
    check_csrf()

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password or len(username) > 180 or len(password) > 256:
        return jsonify({"error": "USERNAME OR PASSWORD IS INCORRECT"}), 400

    rate_key, locked = too_many_wrong(username)
    if locked:
        return jsonify({"error": "TOO MANY TRIES. TRY LATER"}), 429

    try:
        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s LIMIT 1",
            (username,),
        )
        user = cur.fetchone()
        cur.close()
    except mysql.connector.Error:
        app.logger.exception("Database error during login")
        return jsonify({"error": "DATABASE ERROR"}), 503

    saved_hash = user["password_hash"] if user else fake_hash_for_timing
    ok = password_ok(password, saved_hash)

    if not user or not ok:
        add_wrong_try(rate_key)
        return jsonify({"error": "USERNAME OR PASSWORD IS INCORRECT"}), 401

    bad_logins.pop(rate_key, None)
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    csrf_token()

    return jsonify({"ok": True, "next": "/dashboard"})


@app.post("/api/logout")
def logout():
    check_csrf()
    session.clear()
    return jsonify({"ok": True, "next": "/"})


@app.cli.command("create-user")
@click.argument("username")
@click.argument("password")
def create_user(username, password):
    username = username.strip()
    if not username:
        click.echo("Username is required.")
        raise SystemExit(1)

    if len(password) < 8:
        click.echo("Password must be at least 8 chars.")
        raise SystemExit(1)

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    db = mysql.connector.connect(**db_config())
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            (username, hashed),
        )
        db.commit()
        click.echo(f"User created: {username}")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_DUP_ENTRY:
            click.echo("That username already exists.")
        else:
            raise
    finally:
        cur.close()
        db.close()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
