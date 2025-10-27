# ✅ Astra MarketMind – 100% Production Backend (Realtime DB only)
# Brokers Supported: AngelOne (SmartAPI + TOTP), Zerodha, Upstox, Dhan
# Secure Encrypted Firebase Realtime Database Integration + AngelOne Profile Sync

import os
import json
import logging
import datetime
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, db
from cryptography.fernet import Fernet, InvalidToken

# -------------------------
# Basic config
# -------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("astra-backend")

app = Flask(__name__)
CORS(app)

# -------------------------
# Environment variables
# -------------------------
FIREBASE_KEY = os.environ.get("FIREBASE_KEY")
FERNET_KEY = os.environ.get("FERNET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ANGEL_API_KEY = os.environ.get("ANGEL_API_KEY", "").strip()

if not FIREBASE_KEY or not FERNET_KEY or not DATABASE_URL:
    raise Exception("❌ FIREBASE_KEY, FERNET_KEY, and DATABASE_URL are required")

# -------------------------
# Firebase (Realtime DB only)
# -------------------------
try:
    firebase_dict = json.loads(FIREBASE_KEY)
    cred = credentials.Certificate(firebase_dict)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred, {"databaseURL": DATABASE_URL})
    logger.info("✅ Firebase Realtime Database initialized successfully.")
except Exception as e:
    logger.exception("❌ Firebase initialization failed")
    raise

# -------------------------
# Fernet setup
# -------------------------
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def encrypt_text(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode() if plain else ""

def decrypt_text(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        logger.warning("⚠️ Invalid token during decrypt")
        return ""

# -------------------------
# Auth decorator
# -------------------------
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing Authorization header"}), 401
        id_token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = auth.verify_id_token(id_token)
            request.user = {"uid": decoded.get("uid"), "email": decoded.get("email")}
            return fn(*args, **kwargs)
        except Exception as e:
            logger.exception("Token verification failed")
            return jsonify({"ok": False, "error": "Invalid Firebase ID token"}), 401
    return wrapper

# -------------------------
# Health check
# -------------------------
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "message": "Backend Connected Successfully!", "time": datetime.datetime.utcnow().isoformat()}), 200

# -------------------------
# Signup & Login
# -------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        email, password = data.get("email"), data.get("password")
        name = data.get("displayName", "")
        if not email or not password:
            return jsonify({"ok": False, "error": "Email & password required"}), 400

        user = auth.create_user(email=email, password=password, display_name=name)
        ref = db.reference(f"Users/{user.uid}")
        ref.set({
            "email": email,
            "name": name,
            "createdAt": datetime.datetime.utcnow().isoformat(),
            "mode": "paper",
            "brokerAccounts": {},
            "brokers": {}
        })
        return jsonify({"ok": True, "uid": user.uid, "message": "User created"}), 201
    except Exception as e:
        logger.exception("Signup failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True)
        id_token = data.get("idToken")
        if not id_token:
            return jsonify({"ok": False, "error": "idToken required"}), 400
        decoded = auth.verify_id_token(id_token)
        uid = decoded.get("uid")
        db.reference(f"Users/{uid}/lastLogin").set(datetime.datetime.utcnow().timestamp())
        return jsonify({"ok": True, "uid": uid, "email": decoded.get("email"), "message": "Login successful"}), 200
    except Exception as e:
        logger.exception("Login failed")
        return jsonify({"ok": False, "error": str(e)}), 401

# -------------------------
# AngelOne SmartAPI login + profile sync
# -------------------------
SMARTAPI_LOGIN_URL = "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword"
SMARTAPI_PROFILE_URL = "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"

@app.route("/api/broker/angelone/login_by_password", methods=["POST"])
@require_auth
def angelone_login_by_password():
    try:
        body = request.get_json(force=True)
        api_key = body.get("api_key") or ANGEL_API_KEY
        client_code = body.get("client_code") or body.get("client_id")
        password = body.get("password")
        totp = body.get("totp")

        if not all([api_key, client_code, password]):
            return jsonify({"ok": False, "error": "api_key, client_code, and password required"}), 400

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-PrivateKey": api_key,
            "X-UserType": "USER",
            "X-SourceID": "WEB"
        }
        payload = {"clientcode": client_code, "password": password}
        if totp:
            payload["totp"] = totp

        resp = requests.post(SMARTAPI_LOGIN_URL, json=payload, headers=headers, timeout=15)
        data = resp.json()
        if not data.get("status"):
            return jsonify({"ok": False, "error": data.get("message", "Login failed")}), 401

        tokens = data.get("data", {})
        uid = request.user["uid"]

        encrypted = {
            "access_token": encrypt_text(tokens.get("jwtToken", "")),
            "refresh_token": encrypt_text(tokens.get("refreshToken", "")),
            "feed_token": encrypt_text(tokens.get("feedToken", ""))
        }
        broker_info = {
            **encrypted,
            "client_code": client_code,
            "connected_at": datetime.datetime.utcnow().isoformat()
        }
        db.reference(f"Users/{uid}/brokers/angelone").set(broker_info)

        # Fetch and store profile info
        prof_headers = {
            "Authorization": f"Bearer {tokens.get('jwtToken')}",
            "X-ClientCode": client_code,
            "Accept": "application/json"
        }
        profile = requests.get(SMARTAPI_PROFILE_URL, headers=prof_headers, timeout=10).json()
        db.reference(f"Users/{uid}/brokers/angelone/profile").set(profile)

        return jsonify({
            "ok": True,
            "message": "AngelOne SmartAPI verified & profile synced",
            "profile": profile
        }), 200

    except Exception as e:
        logger.exception("AngelOne login error")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Add Trading Account
# -------------------------
@app.route("/api/user/add_trading_account", methods=["POST"])
@require_auth
def add_trading_account():
    try:
        data = request.get_json(force=True)
        uid = request.user["uid"]
        mode = data.get("mode", "real")

        if mode == "real":
            broker_name = data.get("broker_name")
            api_key = data.get("api_key")
            client_id = data.get("client_id")
            access_token = data.get("access_token", "")
            if not all([broker_name, api_key, client_id]):
                return jsonify({"ok": False, "error": "Missing broker_name, api_key, client_id"}), 400
            account_data = {
                "broker_name": broker_name,
                "api_key": encrypt_text(api_key),
                "client_id": client_id,
                "access_token": encrypt_text(access_token),
                "margin_balance": data.get("margin_balance", 0),
                "positions": [],
                "last_updated": datetime.datetime.utcnow().isoformat()
            }
        else:
            account_data = {
                "broker_name": "virtual",
                "balance": data.get("balance", 100000),
                "positions": [],
                "last_updated": datetime.datetime.utcnow().isoformat()
            }

        db.reference(f"Users/{uid}/brokerAccounts/{mode}").set(account_data)
        return jsonify({"ok": True, "message": f"{mode.capitalize()} trading account added successfully!"}), 200
    except Exception as e:
        logger.exception("Add trading account failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Get Trading Account
# -------------------------
@app.route("/api/user/get_trading_account", methods=["POST"])
@require_auth
def get_trading_account():
    try:
        data = request.get_json(force=True)
        uid = request.user["uid"]
        mode = data.get("mode", "real")

        acc = db.reference(f"Users/{uid}/brokerAccounts/{mode}").get()
        if not acc:
            return jsonify({"ok": False, "error": f"No {mode} account found"}), 404

        if mode == "real":
            acc["api_key"] = decrypt_text(acc.get("api_key", ""))
            acc["access_token"] = decrypt_text(acc.get("access_token", ""))

        return jsonify({"ok": True, "mode": mode, "account": acc}), 200
    except Exception as e:
        logger.exception("Get trading account failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Broker List / Disconnect
# -------------------------
@app.route("/api/broker/list", methods=["GET"])
@require_auth
def broker_list():
    try:
        uid = request.user["uid"]
        brokers = db.reference(f"Users/{uid}/brokers").get() or {}
        return jsonify({"ok": True, "brokers": brokers}), 200
    except Exception as e:
        logger.exception("Broker list failed")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/broker/disconnect", methods=["POST"])
@require_auth
def broker_disconnect():
    try:
        data = request.get_json(force=True)
        broker = data.get("broker")
        if not broker:
            return jsonify({"ok": False, "error": "broker required"}), 400
        uid = request.user["uid"]
        db.reference(f"Users/{uid}/brokers/{broker.lower()}").delete()
        return jsonify({"ok": True, "message": f"{broker} disconnected"}), 200
    except Exception as e:
        logger.exception("Broker disconnect failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Mode Switch
# -------------------------
@app.route("/api/user/switch_mode", methods=["POST"])
@require_auth
def switch_mode():
    try:
        data = request.get_json(force=True)
        mode = data.get("mode")
        if mode not in ["paper", "real"]:
            return jsonify({"ok": False, "error": "Invalid mode"}), 400
        uid = request.user["uid"]
        db.reference(f"Users/{uid}/mode").set(mode)
        return jsonify({"ok": True, "message": f"Mode switched to {mode}"}), 200
    except Exception as e:
        logger.exception("Switch mode failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Run server
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"🚀 Flask running on port {port}")
    app.run(host="0.0.0.0", port=port)
