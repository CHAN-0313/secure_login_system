# Secure Login System (Flask)

## Requirements
- **Python 3.12 or 3.13** (Python 3.14 is NOT supported — Pillow has no
  prebuilt wheels for it yet and will fail to build on Windows)

Check your version first:
```bash
python --version
```
If it shows `3.14.x`, install Python 3.12 from python.org before continuing.

## Setup (Windows - PowerShell)
```powershell
python -m venv venv
venv\Scripts\activate
```
If activation is blocked with an "execution policy" error, run this once:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
venv\Scripts\Activate.ps1
```
Or just use Command Prompt instead of PowerShell:
```cmd
venv\Scripts\activate.bat
```

## Setup (macOS/Linux)
```bash
python3 -m venv venv
source venv/bin/activate
```

## Install & Run
```bash
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```
Open: http://127.0.0.1:5000

## If `pip install` fails on Pillow/qrcode
This means Python 3.14 is active. Recreate the venv with Python 3.12:
```bash
deactivate
rmdir /s /q venv      # Windows
rm -rf venv            # macOS/Linux
python3.12 -m venv venv
```
Then activate it again and re-run `pip install -r requirements.txt`.

## Features
- Registration with strong password rules (Werkzeug PBKDF2 hashing)
- Login with 5-attempt lockout (15 min)
- Session-based auth (Flask-Login), CSRF protection (Flask-WTF)
- Dashboard with login stats & security score
- Optional 2FA (TOTP + QR code, Google Authenticator compatible)
- Activity logging (login, failed login, logout, 2FA changes)

## Notes
- Database (SQLite) auto-creates on first run at `database/app.db`.
- Change `SECRET_KEY` env var before any real deployment.
- All required packages (including `email-validator`, `pyotp`, `qrcode`,
  `Pillow`) are listed in `requirements.txt` — install them all in one
  `pip install -r requirements.txt` command rather than one at a time, so
  a single failed package doesn't silently skip the rest.
