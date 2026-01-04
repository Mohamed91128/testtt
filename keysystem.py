from flask import Flask, request, jsonify, render_template, session
from datetime import datetime, timedelta
import uuid
import json
import os
from cryptography.fernet import Fernet

# ================== CONFIG ==================
app = Flask(__name__)
app.secret_key = "AsbspbOBOvOboVOVObsobOBOBowsbdoehshdbahahaj"

KEYS_FILE = "keys.json"

ENCRYPTION_KEY = b"hQ4S1jT1TfQcQk_XLhJ7Ky1n3ht9ABhxqYUt09Ax0CM="
cipher = Fernet(ENCRYPTION_KEY)

KEY_VALID_HOURS = 24
NEW_KEY_WAIT_HOURS = 6
# ============================================


def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, "r") as f:
        return json.load(f)


def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=4)


def generate_unique_key(existing_keys):
    while True:
        key = str(uuid.uuid4())
        if key not in existing_keys:
            return key


# ================== ROUTES ==================

@app.route("/genkey")
def genkey():
    keys = load_keys()
    user_ip = request.remote_addr
    now = datetime.now()

    # 1️⃣ لو اليوزر عنده مفتاح في السيشن → رجعه
    if "user_key" in session:
        key = session["user_key"]
        info = keys.get(key)

        if info and datetime.fromisoformat(info["expires_at"]) > now:
            encrypted = cipher.encrypt(key.encode()).decode()
            return render_template(
                "keygen.html",
                key=encrypted,
                expires=info["expires_at"]
            )

    # 2️⃣ تحقق من IP (6 ساعات)
    for k, info in keys.items():
        if info["ip"] == user_ip:
            next_time = datetime.fromisoformat(info["next_gen_at"])
            if now < next_time:
                remaining = int((next_time - now).total_seconds() / 60)
                return f"❌ You must wait {remaining} minutes before generating a new key", 429

    # 3️⃣ توليد مفتاح جديد
    new_key = generate_unique_key(keys)

    keys[new_key] = {
        "ip": user_ip,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=KEY_VALID_HOURS)).isoformat(),
        "next_gen_at": (now + timedelta(hours=NEW_KEY_WAIT_HOURS)).isoformat()
    }

    save_keys(keys)
    session["user_key"] = new_key

    encrypted = cipher.encrypt(new_key.encode()).decode()

    return render_template(
        "keygen.html",
        key=encrypted,
        expires=keys[new_key]["expires_at"]
    )


@app.route("/verify")
def verify():
    encrypted_key = request.args.get("key")

    if not encrypted_key:
        return jsonify({"valid": False, "reason": "Missing key"}), 400

    try:
        key = cipher.decrypt(encrypted_key.encode()).decode()
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid encryption"}), 400

    keys = load_keys()
    info = keys.get(key)

    if not info:
        return jsonify({"valid": False, "reason": "Key not found"}), 404

    if datetime.fromisoformat(info["expires_at"]) < datetime.now():
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    return jsonify({
        "valid": True,
        "expires_at": info["expires_at"]
    })


# ================== RUN ==================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
