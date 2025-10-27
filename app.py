# app.py (put this at D:\AstraMarketMind\backend\auth\app.py)
import os
import json
import logging
import datetime
import requests
from functools import wraps
from flask import Flask, request, jsonify, redirect
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
ANGEL_PUBLISHER_LOGIN = os.environ.get("ANGEL_PUBLISHER_LOGIN",
                                       "https://smartapi.angelbroking.com/publisher-login")

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
    logger.info("Firebase initialized")
except Exception as e:
    logger.exception("Failed to initialize Firebase")
    raise

# -------------------------
# Fernet crypto
# -------------------------
try:
    fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
except Exception as e:
    logger.exception("Invalid FERNET_KEY")
    raise

def encrypt_text(plain: str) -> str:
    if plain is None:
        return ""
    return fernet.encrypt(plain.encode()).decode()

def decrypt_text(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        logger.warning("Invalid token during decrypt")
        raise

# -------------------------
# Auth decorator (expects Firebase ID token in Authorization header)
# -------------------------
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error":"Authorization header missing or invalid"}), 401
        id_token = auth_header.split(" ",1)[1].strip()
        try:
            decoded = auth.verify_id_token(id_token)
            request.user = {"uid": decoded.get("uid"), "email": decoded.get("email")}
            return fn(*args, **kwargs)
        except Exception as e:
            logger.exception("Token verification failed")
            return jsonify({"error":"Invalid ID token","detail":str(e)}), 401
    return wrapper

# -------------------------
# Health
# -------------------------
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"ok":True, "message":"Backend Connected Successfully!", "time": datetime.datetime.utcnow().isoformat()}), 200

# -------------------------
# Signup (Firebase)
# -------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        display_name = data.get("displayName","")
        if not email or not password:
            return jsonify({"error":"Email and password required"}), 400
        user = auth.create_user(email=email, password=password, display_name=display_name)
        uid = user.uid
        user_doc = {
            "email": email, "displayName": display_name,
            "createdAt": firestore.SERVER_TIMESTAMP, "brokers": {}
        }
        db.collection("users").document(uid).set(user_doc)
        return jsonify({"uid":uid, "message":"User created"}), 201
    except Exception as e:
        logger.exception("Signup failed")
        return jsonify({"error": str(e)}), 500

# -------------------------
# Login (verify Firebase idToken)
# -------------------------
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True) or {}
        id_token = data.get("idToken")
        if not id_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                id_token = auth_header.split(" ",1)[1].strip()
        if not id_token:
            return jsonify({"error":"idToken required"}), 400
        decoded = auth.verify_id_token(id_token)
        return jsonify({"uid": decoded.get("uid"), "email": decoded.get("email"), "message":"Login successful"}), 200
    except Exception as e:
        logger.exception("Login verification failed")
        return jsonify({"error": str(e)}), 401

# -------------------------
# Save encrypted broker tokens helper
# -------------------------
def save_broker_tokens(uid: str, broker: str, tokens: dict, meta: dict = None):
    enc = {}
    if tokens.get("jwtToken"):
        enc["access_token"] = encrypt_text(tokens.get("jwtToken"))
    elif tokens.get("access_token"):
        enc["access_token"] = encrypt_text(tokens.get("access_token"))
    elif tokens.get("token"):
        enc["access_token"] = encrypt_text(tokens.get("token"))
    if tokens.get("refreshToken"):
        enc["refresh_token"] = encrypt_text(tokens.get("refreshToken"))
    if tokens.get("feedToken"):
        enc["feed_token"] = encrypt_text(tokens.get("feedToken"))
    broker_doc = {**enc, "meta": meta or {}, "connected_at": datetime.datetime.utcnow().isoformat()}
    db.collection("users").document(uid).set({"brokers": {broker: broker_doc}}, merge=True)
    logger.info("Saved tokens for %s/%s", uid, broker)

# -------------------------
# AngelOne: Option A - backend loginByPassword (user submits clientcode + mpin/totp)
# Docs: loginByPassword endpoint is official SmartAPI approach. See SmartAPI docs/forum. :contentReference[oaicite:1]{index=1}
# -------------------------
SMARTAPI_LOGIN_BY_PASSWORD = "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword"
SMARTAPI_GET_PROFILE = "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"

@app.route("/api/broker/angelone/login_by_password", methods=["POST"])
@require_auth
def angelone_login_by_password():
    """
    Backend flow: client posts client_code, mpin/password, optional totp.
    Backend calls SmartAPI loginByPassword and returns tokens (not storing until /connect).
    """
    try:
        body = request.get_json(force=True) or {}
        api_key = body.get("api_key") or ANGEL_API_KEY
        if not api_key:
            return jsonify({"ok":False, "error":"ANGEL_API_KEY missing on server or not provided"}), 500

        client_code = body.get("client_code")
        mpin = body.get("mpin") or body.get("password")
        totp = body.get("totp")

        if not client_code or not mpin:
            return jsonify({"ok":False, "error":"client_code and mpin/password required"}), 400

        headers = {
            "Content-Type":"application/json",
            "Accept":"application/json",
            "X-PrivateKey": api_key,
            "X-UserType":"USER",
            "X-SourceID":"WEB"
        }
        payload = {"clientcode": client_code, "password": mpin}
        if totp:
            payload["totp"] = totp

        resp = requests.post(SMARTAPI_LOGIN_BY_PASSWORD, json=payload, headers=headers, timeout=15)
        try:
            j = resp.json()
        except Exception:
            return jsonify({"ok":False, "error":"invalid response from SmartAPI","status_code": resp.status_code, "text": resp.text[:1000]}), 502

        if resp.status_code in (200,201) and (j.get("status") is True or j.get("data")):
            data = j.get("data") or j
            tokens = {
                "jwtToken": data.get("jwtToken"),
                "refreshToken": data.get("refreshToken"),
                "feedToken": data.get("feedToken")
            }
            # DO NOT store tokens here automatically — wait for client to call /connect
            return jsonify({"ok":True, "tokens": tokens, "profile_raw": data}), 200
        else:
            return jsonify({"ok":False, "error":"SmartAPI login failed", "detail": j}), 401

    except Exception as e:
        logger.exception("angelone login_by_password failed")
        return jsonify({"ok":False, "error": str(e)}), 500

# -------------------------
# AngelOne: Option B - Publisher-login (redirect) flow
# - Server provides publisher-login URL to client which opens in browser.
# - SmartAPI redirects back to your configured callback URL with auth_token (subject to SmartAPI behaviour).
# - You need to register redirect in SmartAPI app settings.
# Docs: publisher-login described in SmartAPI docs. :contentReference[oaicite:2]{index=2}
# -------------------------
@app.route("/api/broker/angelone/start", methods=["GET"])
def angelone_start():
    """
    Returns the publisher-login URL for the client to open. Server must have ANGEL_API_KEY in env.
    Client should open this URL (CustomTab / browser). SmartAPI will redirect to the app's registered redirect URL.
    """
    if not ANGEL_API_KEY:
        return jsonify({"ok":False, "error":"ANGEL_API_KEY not configured on server"}), 500
    # you can append state param (e.g., client app state) and redirect param if SmartAPI supports it
    url = f"{ANGEL_PUBLISHER_LOGIN}?api_key={ANGEL_API_KEY}"
    return jsonify({"ok":True, "url": url}), 200

# Example callback — IMPORTANT: set this exact callback URL in SmartAPI app settings.
# SmartAPI may pass auth_token or auth_code depending on their configuration.
@app.route("/api/broker/angelone/callback", methods=["GET"])
def angelone_callback():
    """
    Example callback endpoint. SmartAPI may redirect with 'auth_token' or similar query param.
    This endpoint tries to exchange the returned token with resp from SmartAPI.
    Adapt if SmartAPI returns a different param name.
    """
    try:
        auth_token = request.args.get("auth_token") or request.args.get("auth_code") or request.args.get("token")
        if not auth_token:
            return jsonify({"ok":False, "error":"Missing auth token in callback query"}), 400

        # Attempt to exchange via loginByBroker-like endpoint (some integrations use different endpoints).
        # This block uses a generic /loginByBroker path if available; otherwise log and return token to client.
        exchange_url = "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByBroker"
        headers = {"Content-Type":"application/json", "X-PrivateKey": ANGEL_API_KEY, "Accept":"application/json"}
        payload = {"auth_token": auth_token, "api_key": ANGEL_API_KEY, "api_secret": ANGEL_API_SECRET}
        try:
            resp = requests.post(exchange_url, json=payload, headers=headers, timeout=15)
            j = resp.json()
            if resp.status_code in (200,201) and (j.get("status") is True or j.get("data")):
                data = j.get("data") or j
                # return tokens to caller (you may choose to save after user confirmation)
                return jsonify({"ok":True, "tokens": data}), 200
            else:
                # If exchange not supported, return the raw callback token for client to pass to /login_by_password or other flow
                return jsonify({"ok":False, "error":"Exchange failed","response": j}), 502
        except Exception as e:
            logger.exception("exchange failed")
            return jsonify({"ok":False, "error":"exchange request failed", "detail": str(e)}), 502

    except Exception as e:
        logger.exception("angelone callback failed")
        return jsonify({"ok":False, "error": str(e)}), 500

# -------------------------
# /api/broker/connect : save tokens after verification (client calls this after verifying tokens)
# -------------------------
@app.route("/api/broker/connect", methods=["POST"])
@require_auth
def broker_connect():
    try:
        data = request.get_json(force=True) or {}
        broker = data.get("broker")
        tokens = data.get("tokens") or {}
        meta = data.get("meta") or {}
        if not broker or not tokens:
            return jsonify({"ok":False, "error":"broker and tokens required"}), 400
        uid = request.user["uid"]
        save_broker_tokens(uid, broker.lower(), tokens, meta)
        return jsonify({"ok":True, "broker": broker, "message":"Broker connected and tokens saved"}), 200
    except Exception as e:
        logger.exception("broker_connect failed")
        return jsonify({"ok":False, "error": str(e)}), 500

# -------------------------
# Broker list & disconnect (same as earlier)
# -------------------------
@app.route("/api/broker/list", methods=["GET"])
@require_auth
def broker_list():
    uid = request.user["uid"]
    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        return jsonify({"ok":False,"error":"User not found"}), 404
    data = doc.to_dict() or {}
    brokers = data.get("brokers", {})
    safe = {k: {"meta": v.get("meta"), "connected_at": v.get("connected_at")} for k,v in brokers.items()}
    return jsonify({"ok":True, "brokers": safe}), 200

@app.route("/api/broker/disconnect", methods=["POST"])
@require_auth
def broker_disconnect():
    try:
        data = request.get_json(force=True) or {}
        broker = data.get("broker")
        if not broker:
            return jsonify({"ok":False, "error":"broker required"}), 400
        uid = request.user["uid"]
        user_ref = db.collection("users").document(uid)
        doc = user_ref.get()
        if not doc.exists:
            return jsonify({"ok":False,"error":"User not found"}), 404
        user_doc = doc.to_dict() or {}
        brokers = user_doc.get("brokers", {})
        if broker.lower() in brokers:
            brokers.pop(broker.lower())
            user_ref.set({"brokers": brokers}, merge=True)
            return jsonify({"ok":True,"message":"Broker disconnected"}), 200
        else:
            return jsonify({"ok":False,"error":"Broker not connected"}), 404
    except Exception as e:
        logger.exception("broker_disconnect failed")
        return jsonify({"ok":False,"error": str(e)}), 500

# -------------------------
# Run (dev)
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Flask on port %s", port)
    app.run(host="0.0.0.0", port=port)
