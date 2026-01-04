from flask import Flask, request, jsonify, render_template, abort, redirect
from datetime import datetime, timedelta
import uuid
import json
import os
import secrets
import requests
from cryptography.fernet import Fernet

app = Flask(__name__)

# ---------------- CONFIG ----------------

DB_FILE = "tokens.json"

ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

LINKJUST_API_KEY = "cb67f89fc200c832a9cbd93b926ecedba0f49151"
BASE_URL = "https://testtt-gzh8.onrender.com"

# ---------------- DB HELPERS ----------------

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

# ---------------- START (ENTRY POINT) ----------------

@app.route("/start")
def start():
    token = secrets.token_hex(16)

    destination = f"{BASE_URL}/genkey?token={token}"
    api_url = f"https://linkjust.com/api?api={LINKJUST_API_KEY}&url={destination}"

    try:
        r = requests.get(api_url, timeout=10)
        data = r.json()
    except Exception as e:
        return f"LinkJust API error: {e}", 500

    if data.get("status") == "error":
        return data.get("message", "Link generation failed"), 500

    return redirect(data["shortenedUrl"])

# ---------------- GENKEY ----------------

@app.route("/genkey")
def genkey():
    token = request.args.get("token")
    if not token:
        abort(403, "No token")

    db = load_db()

    # Anti-refresh → same key
    if token in db:
        return render_template(
            "keygen.html",
            key=db[token]["encrypted"],
            expires=db[token]["expires"]
        )

    raw_key = str(uuid.uuid4())
    encrypted_key = cipher.encrypt(raw_key.encode()).decode()
    expires = (datetime.now() + timedelta(hours=24)).isoformat()

    db[token] = {
        "key": raw_key,
        "encrypted": encrypted_key,
        "expires": expires,
        "used": False
    }

    save_db(db)

    return render_template(
        "keygen.html",
        key=encrypted_key,
        expires=expires
    )

# ---------------- VERIFY ----------------

@app.route("/verify")
def verify():
    encrypted = request.args.get("key")
    if not encrypted:
        return jsonify({"valid": False, "reason": "No key"}), 400

    try:
        raw_key = cipher.decrypt(encrypted.encode()).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid encryption"}), 400

    db = load_db()

    for token, data in db.items():
        if data["key"] == raw_key:
            if data["used"]:
                return jsonify({"valid": False, "reason": "Key already used"}), 403

            if datetime.fromisoformat(data["expires"]) < datetime.now():
                return jsonify({"valid": False, "reason": "Key expired"}), 403

            db[token]["used"] = True
            save_db(db)
            return jsonify({"valid": True})

    return jsonify({"valid": False, "reason": "Key not found"}), 404
