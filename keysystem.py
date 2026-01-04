from flask import Flask, request, jsonify, render_template, session, abort
from datetime import datetime, timedelta
import uuid
import json
import os
import hashlib
from cryptography.fernet import Fernet
from werkzeug.middleware.proxy_fix import ProxyFix
from threading import Lock

# ================== CONFIG ==================
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "AsbspbOBOvOboVOVObsobOBOBowsbdoehshdbahahaj")

# ✅ Ensure app correctly trusts Render / reverse-proxy headers
# Fixes incorrect IP detection behind proxies (X-Forwarded-For)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# AES-Fernet encryption
ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

# File-based key storage (simple, local)
KEYS_FILE = "keys.json"
KEY_VALID_HOURS = 24
NEW_KEY_WAIT_HOURS = 6

# File read/write locking (prevents race conditions)
lock = Lock()
# ============================================


# ================== HELPER FUNCTIONS ==================

def safe_load_json(filepath):
    """Safely load JSON data with threading lock to avoid race conditions."""
    with lock:
        if not os.path.exists(filepath):
            return {}
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}  # fallback to empty if corrupted


def safe_save_json(filepath, data):
    """Atomically save JSON data to avoid corruption."""
    with lock:
        tmpfile = filepath + ".tmp"
        with open(tmpfile, "w") as f:
            json.dump(data, f, indent=4)
        os.replace(tmpfile, filepath)


def client_fingerprint():
    """
    Returns a hashed fingerprint based on IP + User-Agent.
    This makes it harder to abuse VPN or IP rotation.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = forwarded_for.split(",")[0].strip() if forwarded_for else request.remote_addr
    ua = request.user_agent.string or "unknown"
    fingerprint_raw = f"{ip}|{ua}".encode()
    return hashlib.sha256(fingerprint_raw).hexdigest()


def generate_unique_key(existing_keys):
    """Generates a unique UUID key not present in the store."""
    while True:
        new_key = str(uuid.uuid4())
        if new_key not in existing_keys:
            return new_key


# ================== ROUTES ==================

@app.route("/genkey")
def genkey():
    """
    Secure key generator:
    - Respects proxy headers
    - Prevents duplicate valid keys
    - Uses fingerprint fallback
    - Enforces cooldowns safely
    """
    now = datetime.utcnow()
    keys = safe_load_json(KEYS_FILE)
    fingerprint = client_fingerprint()

    # 1️⃣ Check session-stored key (persistent key per user)
    existing_key = session.get("user_key")
    if existing_key and existing_key in keys:
        info = keys[existing_key]
        if datetime.fromisoformat(info["expires_at"]) > now:
            encrypted = cipher.encrypt(existing_key.encode()).decode()
            return render_template(
                "keygen.html",
                key=encrypted,
                expires=info["expires_at"],
            )

    # 2️⃣ Fallback: check if fingerprint already has a valid or cooling key
    for k, info in keys.items():
        if info["fingerprint"] == fingerprint:
            exp = datetime.fromisoformat(info["expires_at"])
            next_gen = datetime.fromisoformat(info["next_gen_at"])

            if exp > now:
                # Reuse valid key instead of generating a new one
                session["user_key"] = k
                encrypted = cipher.encrypt(k.encode()).decode()
                return render_template("keygen.html", key=encrypted, expires=info["expires_at"])

            if now < next_gen:
                remaining = int((next_gen - now).total_seconds() // 60)
                return (
                    f"❌ You must wait {remaining} minutes before generating a new key.",
                    429,
                )

    # 3️⃣ Generate new key
    new_key = generate_unique_key(keys)
    keys[new_key] = {
        "fingerprint": fingerprint,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=KEY_VALID_HOURS)).isoformat(),
        "next_gen_at": (now + timedelta(hours=NEW_KEY_WAIT_HOURS)).isoformat(),
    }

    # Save and bind session
    safe_save_json(KEYS_FILE, keys)
    session["user_key"] = new_key

    encrypted = cipher.encrypt(new_key.encode()).decode()
    return render_template("keygen.html", key=encrypted, expires=keys[new_key]["expires_at"])


@app.route("/verify")
def verify():
    """
    Verifies the validity of an encrypted key.
    Secure error handling & validation.
    """
    encrypted_key = request.args.get("key")
    if not encrypted_key:
        return jsonify({"valid": False, "reason": "Missing key"}), 400

    try:
        key = cipher.decrypt(encrypted_key.encode(), ttl=None).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid encryption"}), 400

    keys = safe_load_json(KEYS_FILE)
    info = keys.get(key)
    if not info:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    if datetime.fromisoformat(info["expires_at"]) < datetime.utcnow():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    return jsonify(
        {
            "valid": True,
            "expires_at": info["expires_at"],
        }
    )


# ================== SECURITY SETTINGS ==================

@app.after_request
def secure_headers(resp):
    """Add security headers for production deployments."""
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# ================== RUN ==================

if __name__ == "__main__":
    # Instructions for production:
    # - Use HTTPS (session cookies require it for persistence)
    # - Render or reverse proxy should forward X-Forwarded-For and Proto
    app.config.update(
        SESSION_COOKIE_SECURE=True,      # Required for HTTPS
        SESSION_COOKIE_HTTPONLY=True,    # Prevent JS access
        SESSION_COOKIE_SAMESITE="Lax",   # Thwarts CSRF
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    )
    app.run(host="0.0.0.0", port=8080, debug=False)
