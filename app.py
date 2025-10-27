# ✅ Astra MarketMind – Production Backend (AngelOne Verified, Error-Free)
import os
import json
import logging
import datetime
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
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
ANGEL_API_KEY = os.environ.get("ANGEL_API_KEY", "").strip()
ANGEL_API_SECRET = os.environ.get("ANGEL_API_SECRET", "").strip()

if not FIREBASE_KEY or not FERNET_KEY:
    raise Exception("❌ FIREBASE_KEY or FERNET_KEY missing")

# -------------------------
# Firebase initialization
# -------------------------
try:
    firebase_dict = json.loads(FIREBASE_KEY)
    cred = credentials.Certificate(firebase_dict)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
    db = firestore.client()
    logger.info("✅ Firebase initialized successfully.")
except Exception as e:
    logger.exception("❌ Firebase initialization failed")
    raise

# -------------------------
# Fernet setup
# -------------------------
try:
    fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
except Exception:
    logger.exception("❌ Invalid FERNET_KEY")
    raise


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
            return jsonify({"ok": False, "error": "Invalid Firebase ID token", "detail": str(e)}), 401
    return wrapper

# -------------------------
# Health route
# -------------------------
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({
        "ok": True,
        "message": "Backend Connected Successfully!",
        "time": datetime.datetime.utcnow().isoformat()
    }), 200

# -------------------------
# Signup & login
# -------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        email, password = data.get("email"), data.get("password")
        display_name = data.get("displayName", "")
        if not email or not password:
            return jsonify({"ok": False, "error": "Email & password required"}), 400
        user = auth.create_user(email=email, password=password, display_name=display_name)
        db.collection("users").document(user.uid).set({
            "email": email,
            "displayName": display_name,
            "createdAt": firestore.SERVER_TIMESTAMP,
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
            header = request.headers.get("Authorization", "")
            if header.startswith("Bearer "):
                id_token = header.split(" ", 1)[1].strip()
        if not id_token:
            return jsonify({"ok": False, "error": "idToken required"}), 400

        decoded = auth.verify_id_token(id_token)
        return jsonify({
            "ok": True,
            "uid": decoded.get("uid"),
            "email": decoded.get("email"),
            "message": "Login successful"
        }), 200
    except Exception as e:
        logger.exception("Login failed")
        return jsonify({"ok": False, "error": str(e)}), 401

# -------------------------
# Save broker tokens
# -------------------------
def save_broker_tokens(uid: str, broker: str, tokens: dict, meta: dict = None):
    try:
        enc = {}
        if tokens.get("jwtToken"):
            enc["access_token"] = encrypt_text(tokens["jwtToken"])
        if tokens.get("refreshToken"):
            enc["refresh_token"] = encrypt_text(tokens["refreshToken"])
        if tokens.get("feedToken"):
            enc["feed_token"] = encrypt_text(tokens["feedToken"])
        broker_doc = {
            **enc,
            "meta": meta or {},
            "connected_at": datetime.datetime.utcnow().isoformat()
        }
        db.collection("users").document(uid).set({"brokers": {broker: broker_doc}}, merge=True)
        logger.info(f"✅ Tokens saved for user {uid} broker {broker}")
    except Exception:
        logger.exception("❌ Failed to save broker tokens")

# -------------------------
# AngelOne SmartAPI verified login
# -------------------------
SMARTAPI_LOGIN_URL = "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword"

@app.route("/api/broker/angelone/login_by_password", methods=["POST"])
@require_auth
def angelone_login_by_password():
    try:
        body = request.get_json(force=True)
        api_key = body.get("api_key") or ANGEL_API_KEY
        client_code = body.get("client_code")
        mpin = body.get("mpin") or body.get("password")
        totp = body.get("totp")

        if not (api_key and client_code and mpin):
            return jsonify({"ok": False, "error": "api_key, client_code, and password required"}), 400

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-PrivateKey": api_key,
            "X-UserType": "USER",
            "X-SourceID": "WEB"
        }
        payload = {"clientcode": client_code, "password": mpin}
        if totp:
            payload["totp"] = totp

        logger.info(f"📡 SmartAPI request for client {client_code}")
        resp = requests.post(SMARTAPI_LOGIN_URL, json=payload, headers=headers, timeout=15)
        logger.info(f"🔁 Response {resp.status_code} : {resp.text[:400]}")

        try:
            j = resp.json()
        except Exception:
            return jsonify({"ok": False, "error": "Invalid JSON from SmartAPI"}), 502

        if resp.status_code in (200, 201) and j.get("status") is True:
            data = j.get("data", {})
            tokens = {
                "jwtToken": data.get("jwtToken"),
                "refreshToken": data.get("refreshToken"),
                "feedToken": data.get("feedToken")
            }
            uid = request.user["uid"]
            meta = {"client_code": client_code, "verified_at": datetime.datetime.utcnow().isoformat()}
            save_broker_tokens(uid, "angelone", tokens, meta)
            return jsonify({
                "ok": True,
                "verified": True,
                "broker": "angelone",
                "message": "AngelOne SmartAPI verified successfully",
                "tokens": tokens
            }), 200
        else:
            return jsonify({
                "ok": False,
                "verified": False,
                "error": j.get("message") or "SmartAPI verification failed",
                "response": j
            }), 401
    except Exception as e:
        logger.exception("AngelOne SmartAPI verification error")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Broker list / disconnect
# -------------------------
@app.route("/api/broker/list", methods=["GET"])
@require_auth
def broker_list():
    uid = request.user["uid"]
    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        return jsonify({"ok": False, "error": "User not found"}), 404
    brokers = doc.to_dict().get("brokers", {})
    safe = {k: {"meta": v.get("meta"), "connected_at": v.get("connected_at")} for k, v in brokers.items()}
    return jsonify({"ok": True, "brokers": safe}), 200


@app.route("/api/broker/disconnect", methods=["POST"])
@require_auth
def broker_disconnect():
    try:
        data = request.get_json(force=True)
        broker = data.get("broker")
        if not broker:
            return jsonify({"ok": False, "error": "broker required"}), 400
        uid = request.user["uid"]
        user_ref = db.collection("users").document(uid)
        doc = user_ref.get()
        if not doc.exists:
            return jsonify({"ok": False, "error": "User not found"}), 404
        brokers = doc.to_dict().get("brokers", {})
        if broker.lower() in brokers:
            brokers.pop(broker.lower())
            user_ref.set({"brokers": brokers}, merge=True)
            return jsonify({"ok": True, "message": f"{broker} disconnected"}), 200
        return jsonify({"ok": False, "error": "Broker not connected"}), 404
    except Exception as e:
        logger.exception("Broker disconnect failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Run server
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"🚀 Flask running on port {port}")
    app.run(host="0.0.0.0", port=port)
