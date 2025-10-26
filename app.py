# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
import datetime
import os
import json
import logging
from cryptography.fernet import Fernet, InvalidToken
from functools import wraps

# external http requests for broker verification
import requests

# -------------------------
# Basic config & logging
# -------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("astra-backend")

app = Flask(__name__)
CORS(app)  # allow cross-origin requests from Android app

# -------------------------
# Required environment vars
# -------------------------
FIREBASE_KEY = os.environ.get("FIREBASE_KEY")
FERNET_KEY = os.environ.get("FERNET_KEY")

if not FIREBASE_KEY:
    logger.error("FIREBASE_KEY env var missing.")
    raise Exception("❌ FIREBASE_KEY environment variable not found. Please set it.")

if not FERNET_KEY:
    logger.error("FERNET_KEY env var missing.")
    raise Exception("❌ FERNET_KEY environment variable not found. Generate via Fernet.generate_key() and set it.")

# -------------------------
# Initialize Firebase
# -------------------------
try:
    firebase_dict = json.loads(FIREBASE_KEY)
    cred = credentials.Certificate(firebase_dict)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
    db = firestore.client()
    logger.info("✅ Firebase initialized.")
except Exception as e:
    logger.exception("Failed to initialize Firebase.")
    raise

# -------------------------
# Fernet helper
# -------------------------
try:
    fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
except Exception as e:
    logger.exception("Invalid FERNET_KEY")
    raise


def encrypt_text(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode()


def decrypt_text(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        logger.warning("Invalid token during decrypt")
        raise


# -------------------------
# Auth decorator: expects Authorization: Bearer <idToken>
# -------------------------
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing or invalid"}), 401

        id_token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = auth.verify_id_token(id_token)
            request.user = {
                "uid": decoded.get("uid"),
                "email": decoded.get("email")
            }
            return fn(*args, **kwargs)
        except Exception as e:
            logger.exception("Token verification failed")
            return jsonify({"error": "Invalid ID token", "detail": str(e)}), 401

    return wrapper


# -------------------------
# Health / ping
# -------------------------
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({
        "ok": True,
        "message": "Backend Connected Successfully!",
        "time": datetime.datetime.utcnow().isoformat()
    }), 200


# -------------------------
# Signup
# -------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        display_name = data.get("displayName", "")

        if not email or not password:
            return jsonify({"error": "Email and Password required"}), 400

        user_rec = auth.create_user(email=email, password=password, display_name=display_name)
        uid = user_rec.uid

        user_doc = {
            "email": email,
            "displayName": display_name,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "role": "user",
            "mode": "paper",
            "preferences": {},
            "kyc_completed": False,
            "brokers": {}
        }
        db.collection("users").document(uid).set(user_doc)

        return jsonify({"uid": uid, "message": "User created successfully!"}), 201
    except Exception as e:
        logger.exception("Signup failed")
        return jsonify({"error": str(e)}), 500


# -------------------------
# Login
# -------------------------
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
        uid = decoded.get("uid")
        email = decoded.get("email")
        return jsonify({"uid": uid, "email": email, "message": "Login successful"}), 200
    except Exception as e:
        logger.exception("Login verification failed")
        return jsonify({"error": str(e)}), 401


# -------------------------
# Broker: Verify credentials (AngelOne / Upstox / Zerodha)
# - This does a quick verification step before storing tokens.
# - Returns ok: true + user info if verification passes.
# -------------------------
@app.route("/api/broker/verify", methods=["POST"])
@require_auth
def broker_verify():
    try:
        data = request.get_json(force=True) or {}
        broker_name = (data.get("broker") or "").strip().lower()
        access_token = data.get("access_token")
        api_key = data.get("api_key") or data.get("access_token')", access_token)  # fallback
        api_secret = data.get("api_secret") or data.get("refresh_token")
        meta = data.get("meta", {})

        if not broker_name or not (access_token or api_key):
            return jsonify({"ok": False, "error": "broker and access_token/api_key required"}), 400

        verified = False
        user_info = {}

        # --- Zerodha: simple demo-match rule (adjust to your real Zerodha verification)
        if broker_name == "zerodha":
            # for demo: if api key startswith demo treat as verified
            if (api_key or "").startswith("demo") or (access_token or "").startswith("demo"):
                verified = True
                user_info = {
                    "broker": "Zerodha",
                    "client_id": "ZRD-DEMO-123",
                    "name": "Zerodha Demo User"
                }

        # --- AngelOne / SmartAPI verification (example)
        elif broker_name in ("angelone", "angel", "angel broking", "angelbroking"):
            try:
                # AngelOne endpoints & headers differ in real; this is an example attempt.
                # Use actual production/sandbox URLs and header names from AngelOne docs.
                angel_url = "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
                resp = requests.get(angel_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    j = resp.json()
                    # check shape depending on AngelOne response
                    # if j contains data or clientcode, treat as verified
                    if isinstance(j, dict) and (j.get("data") or j.get("clientcode") or j.get("status") == "success"):
                        # normalize user info if available
                        data_block = j.get("data") or j
                        verified = True
                        user_info = {
                            "broker": "AngelOne",
                            "client_id": data_block.get("clientcode", data_block.get("client_id", "ANG-DEMO")),
                            "name": data_block.get("name", data_block.get("clientName", "Angel Demo"))
                        }
                else:
                    logger.info(f"AngelOne verify returned code {resp.status_code}: {resp.text[:300]}")
            except Exception as e:
                logger.warning(f"AngelOne verify request failed: {e}")

        # --- Upstox verification example
        elif broker_name == "upstox":
            try:
                upstox_url = "https://api.upstox.com/v2/user/profile"
                headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
                resp = requests.get(upstox_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    j = resp.json()
                    # Upstox returns user profile under 'data' commonly
                    data_block = j.get("data") if isinstance(j, dict) else None
                    if data_block:
                        verified = True
                        user_info = {
                            "broker": "Upstox",
                            "client_id": data_block.get("client_id", "UPSTOX-DEMO"),
                            "name": data_block.get("name", "Upstox Demo")
                        }
                else:
                    logger.info(f"Upstox verify returned code {resp.status_code}: {resp.text[:300]}")
            except Exception as e:
                logger.warning(f"Upstox verify request failed: {e}")

        # --- Add other brokers here as needed (AngelOne sandbox vs prod, etc.)

        if verified:
            return jsonify({
                "ok": True,
                "verified": True,
                "broker": broker_name,
                "user": user_info,
                "message": f"{broker_name.capitalize()} verified successfully."
            }), 200
        else:
            return jsonify({
                "ok": False,
                "verified": False,
                "broker": broker_name,
                "message": f"Invalid or unverified credentials for {broker_name}."
            }), 401

    except Exception as e:
        logger.exception("broker_verify failed")
        return jsonify({"ok": False, "error": str(e)}), 500


# -------------------------
# Broker: Connect (store encrypted tokens after verification)
# POST /api/broker/connect
# -------------------------
@app.route("/api/broker/connect", methods=["POST"])
@require_auth
def broker_connect():
    try:
        data = request.get_json(force=True) or {}
        broker_name = data.get("broker")
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        meta = data.get("meta", {})

        if not broker_name or not access_token:
            return jsonify({"error": "broker and access_token required"}), 400

        uid = request.user["uid"]
        enc_access = encrypt_text(access_token)
        enc_refresh = encrypt_text(refresh_token) if refresh_token else None

        broker_doc = {
            "access_token": enc_access,
            "refresh_token": enc_refresh,
            "meta": meta,
            "connected_at": datetime.datetime.utcnow().isoformat()
        }

        user_ref = db.collection("users").document(uid)
        user_ref.set({"brokers": {broker_name: broker_doc}}, merge=True)

        logger.info(f"✅ User {uid} connected broker {broker_name}")
        return jsonify({
            "ok": True,
            "broker": broker_name,
            "message": "Broker connected and tokens saved (encrypted)."
        }), 200

    except Exception as e:
        logger.exception("broker_connect failed")
        return jsonify({"error": str(e)}), 500


# -------------------------
# Broker: List
# -------------------------
@app.route("/api/broker/list", methods=["GET"])
@require_auth
def broker_list():
    try:
        uid = request.user["uid"]
        doc = db.collection("users").document(uid).get()
        if not doc.exists:
            return jsonify({"error": "User not found"}), 404

        data = doc.to_dict() or {}
        brokers = data.get("brokers", {})
        safe_brokers = {
            name: {"meta": info.get("meta"), "connected_at": info.get("connected_at")}
            for name, info in brokers.items()
        }

        return jsonify({"ok": True, "brokers": safe_brokers}), 200
    except Exception as e:
        logger.exception("broker_list failed")
        return jsonify({"error": str(e)}), 500


# -------------------------
# Broker: Disconnect
# -------------------------
@app.route("/api/broker/disconnect", methods=["POST"])
@require_auth
def broker_disconnect():
    try:
        data = request.get_json(force=True) or {}
        broker_name = data.get("broker")
        if not broker_name:
            return jsonify({"error": "broker required"}), 400

        uid = request.user["uid"]
        user_ref = db.collection("users").document(uid)
        doc = user_ref.get()
        if not doc.exists:
            return jsonify({"error": "User not found"}), 404

        user_data = doc.to_dict() or {}
        brokers = user_data.get("brokers", {})
        if broker_name in brokers:
            brokers.pop(broker_name)
            user_ref.set({"brokers": brokers}, merge=True)
            return jsonify({"ok": True, "message": f"Broker {broker_name} disconnected"}), 200
        else:
            return jsonify({"error": "Broker not connected"}), 404
    except Exception as e:
        logger.exception("broker_disconnect failed")
        return jsonify({"error": str(e)}), 500


# -------------------------
# Debug Route (for Render verification)
# -------------------------
@app.route("/api/debug/routes", methods=["GET"])
def show_routes():
    routes = [str(r) for r in app.url_map.iter_rules()]
    return jsonify({"routes": routes}), 200


# -------------------------
# Generic error handlers
# -------------------------
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "detail": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server Error", "detail": str(e)}), 500


# -------------------------
# Run (development only)
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("✅ Flask app started successfully!")
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print("➡️", rule)
    app.run(host="0.0.0.0", port=port)
