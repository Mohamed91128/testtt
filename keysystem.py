import secrets
import time
import requests
from urllib.parse import quote_plus
from flask import Flask, redirect, request

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# simple in-memory token store
VALID_TOKENS = {}

LINKJUST_API_KEY = "cb67f89fc200c832a9cbd93b926ecedba0f49151"
BASE_URL = "https://testtt-gzh8.onrender.com"


@app.route("/start")
def start():
    # generate token
    token = secrets.token_hex(16)

    VALID_TOKENS[token] = {
        "used": False,
        "created": time.time()
    }

    # destination MUST be urlencoded
    destination = f"{BASE_URL}/genkey?token={token}"
    encoded_destination = quote_plus(destination)

    api_url = (
        "https://linkjust.com/api"
        f"?api={LINKJUST_API_KEY}"
        f"&url={encoded_destination}"
        f"&alias=key-{token[:6]}"
    )

    try:
        r = requests.get(api_url, timeout=10)
        data = r.json()
    except Exception:
        return "LinkJust API error", 500

    if data.get("status") != "success":
        return f"LinkJust error: {data.get('message')}", 500

    return redirect(data["shortenedUrl"])


@app.route("/genkey")
def genkey():
    token = request.args.get("token")

    if not token or token not in VALID_TOKENS:
        return "Invalid token", 403

    if VALID_TOKENS[token]["used"]:
        return "Token already used", 403

    # mark token as used
    VALID_TOKENS[token]["used"] = True

    # generate final key
    user_key = secrets.token_hex(24)

    return f"""
    <h1>Your Key</h1>
    <p>{user_key}</p>
    """
