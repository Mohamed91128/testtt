from flask import Flask, request, jsonify, render_template, abort, redirect
from datetime import datetime, timedelta
import uuid
import json
import os
import secrets
from cryptography.fernet import Fernet

app = Flask(__name__)

# ================== CONFIG ==================

DB_FILE = "tokens.json"

# KEEP THIS SECRET
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

# Your LinkJust API key (USED ONLY IN URL, NOT API CALL)
LINKJUST_API_KEY = "cb67f89fc200c832a9cbd93b926ecedba0f49151"

# Your Render URL (NO trailing slash)
BASE_URL = "https://testtt-gzh8.onrender.com"

# ================== DB HELPERS ==================

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

# ================== START (ENTRY POINT) ==================

@app.route("/start")
def start():
    token = secrets.token_hex(16)

    # Where LinkJust should send the user AFTER ads
    destination = f"{BASE_URL}/genkey?token={token}"

    # LinkJust browser redirect (NO SERVER API CALL)
    linkjust_url = (
        "https://linkjust.com/"
        "?api=" + LINKJUST_API_KEY +
        "&url=" + destination
    )

    return redirect(linkjust_url)

# ================== GENKEY ==================

@app.route("/genkey")
def genkey():
    token = request.args.get("token")
    if not token:
        abort(403, "No token provided")

    db = load_db()

    # Anti-refresh: return same key
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

# ================== VERIFY ==================

@app.route("/verify")
def verify():
    encrypted = request.args.get("key")
    if not encrypted:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

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

# ================== RUN ==================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
