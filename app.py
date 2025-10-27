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
# Env vars (must set these securely on server)
# -------------------------
FIREBASE_KEY = os.environ.get("FIREBASE_KEY")           # JSON string of serviceAccount.json
FERNET_KEY = os.environ.get("FERNET_KEY")               # Fernet key string
ANGEL_API_KEY = os.environ.get("ANGEL_API_KEY")         # SmartAPI API Key
ANGEL_API_SECRET = os.environ.get("ANGEL_API_SECRET")   # SmartAPI API Secret
ANGEL_PUBLISHER_LOGIN = os.environ.get(
    "ANGEL_PUBLISHER_LOGIN",
    "https://smartapi.angelbroking.com/publisher-login"
)

if not FIREBASE_KEY or not FERNET_KEY:
    logger.error("FIREBASE_KEY or FERNET_KEY missing")
    raise Exception("FIREBASE_KEY and FERNET_KEY must be set as environment variables")

# -------------------------
# Initialize Firebase
# -------------------------
try:
    firebase_dict = json.loads(FIREBASE_KEY)
    cred = credentials.Certificate(firebase_dict)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
    db = firestore.client()
    logger.info("✅ Firebase initialized successfully")
except Exception as e:
    logger.exception("Failed to initialize Firebase")
    raise

# -------------------------
# Fernet crypto setup
# -------------------------
try:
    fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
except Exception as e:
    logger.exception("Invalid FERNET_KEY")
    raise


def encrypt_text(plain: str) -> str:
    if not plain:
        return ""
    return fernet.encrypt(plain.encode()).decode()


def decrypt_text(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        logger.warning("Invalid token during decrypt")
        raise


# -------------------------
# Firebase Auth decorator
# -------------------------
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing or invalid"}), 401
        id_token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = auth.verify_id_token(id_token)
            request.user = {"uid": decoded.get("uid"), "email": decoded.get("email")}
            return fn(*args, **kwargs)
        except Exception as e:
            logger.exception("Token verification failed")
            return jsonify({"error": "Invalid ID token", "detail": str(e)}), 401
    return wrapper


# -------------------------
# Health Check
# -------------------------
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({
        "ok": True,
        "message": "Backend Connected Successfully!",
        "time": datetime.datetime.utcnow().isoformat()
    }), 200


# -------------------------
# Signup & Login Routes
# -------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        display_name = data.get("displayName", "")
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400
        user = auth.create_user(email=email, password=password, display_name=display_name)
        uid = user.uid
        db.collection("users").document(uid).set({
            "email": email,
            "displayName": display_name,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "brokers": {}
        })
        return jsonify({"uid": uid, "message": "User created successfully"}), 201
    except Exception as e:
        logger.exception("Signup failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True) or {}
        id_token = data.get("idToken")
        if not id_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                id_token = auth_header.split(" ", 1)[1].strip()
        if not id_token:
            return jsonify({"error": "idToken required"}), 400
        decoded = auth.verify_id_token(id_token)
        return jsonify({
            "uid": decoded.get("uid"),
            "email": decoded.get("email"),
            "message": "Login successful"
        }), 200
    except Exception as e:
        logger.exception("Login failed")
        return jsonify({"error": str(e)}), 401


# -------------------------
# Helper: Save broker tokens securely
# -------------------------
def save_broker_tokens(uid: str, broker: str, tokens: dict, meta: dict = None):
    enc = {}
    if tokens.get("jwtToken"):
        enc["access_token"] = encrypt_text(tokens.get("jwtToken"))
    if tokens.get("refreshToken"):
        enc["refresh_token"] = encrypt_text(tokens.get("refreshToken"))
    if tokens.get("feedToken"):
        enc["feed_token"] = encrypt_text(tokens.get("feedToken"))
    broker_doc = {
        **enc,
        "meta": meta or {},
        "connected_at": datetime.datetime.utcnow().isoformat()
    }
    db.collection("users").document(uid).set({"brokers": {broker: broker_doc}}, merge=True)
    logger.info(f"✅ Tokens saved for user {uid} broker {broker}")


# -------------------------
# AngelOne SmartAPI Login (Verified Logic)
# -------------------------
SMARTAPI_LOGIN_BY_PASSWORD = (
    "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword"
)
SMARTAPI_GET_PROFILE = (
    "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"
)


@app.route("/api/broker/angelone/login_by_password", methods=["POST"])
@require_auth
def angelone_login_by_password():
    """
    Fully verified SmartAPI login with Firestore save
    """
    try:
        body = request.get_json(force=True)
        api_key = body.get("api_key") or ANGEL_API_KEY
        client_code = body.get("client_code")
        mpin = body.get("mpin") or body.get("password")
        totp = body.get("totp")

        if not api_key or not client_code or not mpin:
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

        resp = requests.post(SMARTAPI_LOGIN_BY_PASSWORD, json=payload, headers=headers, timeout=15)
        logger.info(f"SmartAPI login status: {resp.status_code}")

        try:
            j = resp.json()
        except Exception:
            logger.warning(f"Invalid SmartAPI response: {resp.text[:200]}")
            return jsonify({"ok": False, "error": "Invalid SmartAPI response"}), 502

        if resp.status_code in (200, 201) and j.get("status") is True:
            data = j.get("data", {})
            tokens = {
                "jwtToken": data.get("jwtToken"),
                "refreshToken": data.get("refreshToken"),
                "feedToken": data.get("feedToken")
            }

            uid = request.user["uid"]
            meta = {
                "client_code": client_code,
                "verified_at": datetime.datetime.utcnow().isoformat()
            }
            save_broker_tokens(uid, "angelone", tokens, meta)

            return jsonify({
                "ok": True,
                "verified": True,
                "message": "AngelOne SmartAPI verified successfully",
                "broker": "angelone",
                "tokens": tokens
            }), 200
        else:
            msg = j.get("message") or "SmartAPI verification failed"
            logger.warning(f"AngelOne SmartAPI failed: {msg}")
            return jsonify({"ok": False, "verified": False, "error": msg, "detail": j}), 401

    except Exception as e:
        logger.exception("AngelOne SmartAPI verification error")
        return jsonify({"ok": False, "error": str(e)}), 500


# -------------------------
# Broker connect/list/disconnect
# -------------------------
@app.route("/api/broker/connect", methods=["POST"])
@require_auth
def broker_connect():
    try:
        data = request.get_json(force=True)
        broker = data.get("broker")
        tokens = data.get("tokens")
        meta = data.get("meta", {})
        if not broker or not tokens:
            return jsonify({"ok": False, "error": "broker and tokens required"}), 400
        uid = request.user["uid"]
        save_broker_tokens(uid, broker.lower(), tokens, meta)
        return jsonify({"ok": True, "broker": broker, "message": "Broker connected"}), 200
    except Exception as e:
        logger.exception("Broker connect failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/broker/list", methods=["GET"])
@require_auth
def broker_list():
    uid = request.user["uid"]
    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = doc.to_dict() or {}
    brokers = data.get("brokers", {})
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
        user_data = doc.to_dict() or {}
        brokers = user_data.get("brokers", {})
        if broker.lower() in brokers:
            brokers.pop(broker.lower())
            user_ref.set({"brokers": brokers}, merge=True)
            return jsonify({"ok": True, "message": f"{broker} disconnected"}), 200
        else:
            return jsonify({"ok": False, "error": "Broker not connected"}), 404
    except Exception as e:
        logger.exception("Broker disconnect failed")
        return jsonify({"ok": False, "error": str(e)}), 500


# -------------------------
# Run server
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"🚀 Flask server started on port {port}")
    app.run(host="0.0.0.0", port=port)
