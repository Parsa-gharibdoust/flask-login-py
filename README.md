# Flask Login Py

A small secure login project built with Flask, MySQL, bcrypt, and a simple HTML/CSS frontend.

It includes practical login security basics such as hashed passwords, CSRF protection, parameterized SQL queries, protected sessions, and a private dashboard route.

## Features

- Secure password checking with `bcrypt`
- MySQL users table with hashed passwords
- SQL injection protection with parameterized queries
- CSRF token protection for login and logout requests
- HttpOnly session cookies
- Basic brute-force protection per IP and username
- Security headers for XSS and clickjacking reduction
- Protected dashboard page after successful login
- Short English UI messages

## Project Structure

```text
.
├── api.py
├── login-panel/
│   ├── app.js
│   ├── dashboard.html
│   ├── dashboard.js
│   └── index.html
├── schema.sql
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10+
- MySQL 8+
- pip

## Setup

Clone the project and install the dependencies:

```bash
git clone https://github.com/parsa-ghariboudst/flask-login-py.git
cd flask-login-py

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Create your local environment file:

```bash
cp .env.example .env
```

Edit `.env` and set your own values:

```env
SECRET_KEY=use-a-long-random-secret-here
COOKIE_SECURE=0
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=1

MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your-mysql-password
MYSQL_DATABASE=py_login
```

For production over HTTPS, set:

```env
COOKIE_SECURE=1
FLASK_DEBUG=0
```

## Database Setup

Create the database and users table:

```bash
mysql -u root -p < schema.sql
```

Create a login user:

```bash
flask --app api create-user admin StrongPass123
```

## Run

Start the Flask server:

```bash
python api.py
```

Open the app:

```text
http://127.0.0.1:5000
```

After a successful login, the app redirects to:

```text
/dashboard
```

## Push to GitHub

Initialize Git and push the project:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/parsa-ghariboudst/flask-login-py.git
git push -u origin main
```

If the remote already exists, use:

```bash
git remote set-url origin https://github.com/parsa-ghariboudst/flask-login-py.git
git push -u origin main
```

Do not commit `.env`. Keep `.env.example` as the public config template.

## API Routes

| Method | Route | Description |
| --- | --- | --- |
| `GET` | `/` | Login page |
| `GET` | `/dashboard` | Protected dashboard |
| `GET` | `/api/csrf` | Creates/returns CSRF token |
| `POST` | `/api/login` | Authenticates user |
| `POST` | `/api/logout` | Clears session |

## Security Notes

This project includes the core protections expected from a small login system:

- Passwords are never stored as plain text.
- Login queries use placeholders, not string formatting.
- User-facing messages do not reveal whether the username exists.
- Dashboard access requires a valid server-side session.
- Login/logout requests require a CSRF token.
- User input is written with `textContent` in JavaScript, not injected as HTML.

For a real production deployment, also use HTTPS, a production WSGI server, stronger rate limiting backed by Redis or a database, secure secret management, server logs, monitoring, and regular dependency updates.

## Example Messages

```text
USERNAME OR PASSWORD IS INCORRECT
TOO MANY TRIES. TRY LATER
DATABASE ERROR
LOGIN FAILED
SERVER ERROR
```
