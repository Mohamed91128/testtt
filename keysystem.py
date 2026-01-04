from flask import Flask, request, session, jsonify
import secrets
import time

app = Flask(__name__)

# REQUIRED for sessions
app.secret_key = secrets.token_hex(32)

# In-memory storage (use Redis/DB later if you want)
TOKENS = {}
KEYS = {}

TOKEN_LIFETIME = 60 * 10   # 10 minutes
KEY_LIFETIME = 60 * 60 * 24  # 24 hours


# -----------------------------
# KEY GENERATION PAGE
# -----------------------------
@app.route("/genkey")
def genkey():
    now = time.time()

    # If user already generated a key (ANTI REFRESH)
    if "token" in session:
        token = session["token"]
        if token in TOKENS:
            data = TOKENS[token]
            return f"""
            <h2>Your Key</h2>
            <p style="font-size:20px;">{data['key']}</p>
            <p>Expires in 24 hours</p>
            """

    # First legit visit after LinkJust
    token = secrets.token_hex(16)
    key = secrets.token_hex(32)

    TOKENS[token] = {
        "key": key,
        "created": now,
        "used": False
    }

    KEYS[key] = {
        "created": now,
        "expires": now + KEY_LIFETIME,
        "used": False
    }

    session["token"] = token

    return f"""
    <h2>Your Key</h2>
    <p style="font-size:20px;">{key}</p>
    <p>Do not refresh or share this key.</p>
    """


# -----------------------------
# VERIFY KEY (APP USES THIS)
# -----------------------------
@app.route("/verify")
def verify():
    key = request.args.get("key")
    if not key:
        return jsonify({"valid": False, "reason": "No key"}), 400

    data = KEYS.get(key)
    if not data:
        return jsonify({"valid": False, "reason": "Invalid key"}), 403

    if data["used"]:
        return jsonify({"valid": False, "reason": "Key already used"}), 403

    if time.time() > data["expires"]:
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    data["used"] = True
    return jsonify({"valid": True})


# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.route("/")
def home():
    return "Key system running"


if __name__ == "__main__":
    app.run()
