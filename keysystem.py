from flask import Flask, redirect, request, abort, jsonify
import secrets
import requests
import time

app = Flask(__name__)

# ==============================
# CONFIG
# ==============================
LINKJUST_API_KEY = "cb67f89fc200c832a9cbd93b926ecedba0f49151"
BASE_URL = "https://testtt-gzh8.onrender.com"

# Token storage (use Redis / DB in production)
tokens = {}

# ==============================
# STEP 1: START → SEND TO LINKJUST
# ==============================
@app.route("/start")
def start():
    token = secrets.token_hex(16)

    # save token with timestamp
    tokens[token] = {
        "used": False,
        "created": time.time()
    }

    destination = f"{BASE_URL}/genkey?token={token}"

    api_url = (
        "https://linkjust.com/api"
        f"?api={LINKJUST_API_KEY}"
        f"&url={destination}"
    )

    try:
        r = requests.get(api_url, timeout=10)
        data = r.json()
    except Exception as e:
        return f"LinkJust API error: {e}", 500

    if data.get("status") != "success":
        return f"LinkJust error: {data}", 500

    short_url = data["shortenedUrl"]

    return redirect(short_url)


# ==============================
# STEP 2: AFTER ADS → GENERATE KEY
# ==============================
@app.route("/genkey")
def genkey():
    token = request.args.get("token")

    if not token or token not in tokens:
        abort(403)

    token_data = tokens[token]

    # prevent refresh abuse
    if token_data["used"]:
        return "❌ Token already used", 403

    # expire after 10 minutes
    if time.time() - token_data["created"] > 600:
        return "❌ Token expired", 403

    # mark token as used
    token_data["used"] = True

    # generate the key
    generated_key = secrets.token_hex(24)

    return f"""
    <html>
        <head>
            <title>Your Key</title>
            <style>
                body {{
                    background:#111;
                    color:#0f0;
                    font-family: monospace;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    height:100vh;
                }}
                .box {{
                    background:#000;
                    padding:30px;
                    border:1px solid #0f0;
                    text-align:center;
                }}
            </style>
        </head>
        <body>
            <div class="box">
                <h2>✅ Your Key</h2>
                <p>{generated_key}</p>
                <p>Do NOT refresh this page</p>
            </div>
        </body>
    </html>
    """


# ==============================
# HEALTH CHECK
# ==============================
@app.route("/")
def home():
    return "Keysystem Online"


if __name__ == "__main__":
    app.run()
