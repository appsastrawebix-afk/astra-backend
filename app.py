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
# Broker helper utilities & endpoints
# -------------------------
SMARTAPI_BASE = "https://apiconnect.angelbroking.com"
SMARTAPI_LOGIN_BY_PASSWORD = SMARTAPI_BASE + "/rest/auth/angelbroking/user/v1/loginByPassword"
SMARTAPI_GET_PROFILE = SMARTAPI_BASE + "/rest/secure/angelbroking/user/v1/getProfile"
# SMARTAPI_REFRESH left as placeholder; implement per current SmartAPI docs when needed

ZERODHA_API_BASE = "https://api.kite.trade"
DHAN_API_BASE = "https://api.dhan.co"  # confirm exact base with Dhan docs
UPSTOX_API_BASE = "https://api.upstox.com/v2"


def _safe_get_meta(meta, key):
    try:
        if isinstance(meta, dict):
            return meta.get(key)
    except Exception:
        pass
    return None


def save_broker_tokens_to_firestore(uid: str, broker_name: str, tokens: dict, meta: dict = None):
    """
    Encrypt tokens using fernet and store into Firestore under users/{uid}.brokers.{broker_name}
    tokens is a dict that may contain keys like jwtToken, refreshToken, feedToken, access_token
    """
    enc = {}
    try:
        if tokens.get("jwtToken"):
            enc["access_token"] = encrypt_text(tokens.get("jwtToken"))
        elif tokens.get("access_token"):
            enc["access_token"] = encrypt_text(tokens.get("access_token"))
        else:
            enc["access_token"] = encrypt_text(tokens.get("token") or "")

        if tokens.get("refreshToken"):
            enc["refresh_token"] = encrypt_text(tokens.get("refreshToken"))
        elif tokens.get("refresh_token"):
            enc["refresh_token"] = encrypt_text(tokens.get("refresh_token"))

        if tokens.get("feedToken"):
            enc["feed_token"] = encrypt_text(tokens.get("feedToken"))

    except Exception as e:
        logger.exception("Failed to encrypt tokens: %s", e)
        # continue and save whatever we have

    broker_doc = {
        **enc,
        "meta": meta or {},
        "connected_at": datetime.datetime.utcnow().isoformat()
    }
    user_ref = db.collection("users").document(uid)
    user_ref.set({"brokers": {broker_name: broker_doc}}, merge=True)
    logger.info("Saved encrypted tokens for user %s broker %s", uid, broker_name)


# -------------------------
# Broker verification functions
# -------------------------
def smartapi_login(api_key: str, client_code: str, mpin_or_password: str, totp: str = None,
                   client_local_ip: str = None, client_public_ip: str = None, mac_address: str = None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-PrivateKey": api_key,
        "X-UserType": "USER",
        "X-SourceID": "WEB"
    }
    if client_local_ip:
        headers["X-ClientLocalIP"] = client_local_ip
    if client_public_ip:
        headers["X-ClientPublicIP"] = client_public_ip
    if mac_address:
        headers["X-MACAddress"] = mac_address

    payload = {
        "clientcode": client_code,
        "password": mpin_or_password
    }
    if totp:
        payload["totp"] = totp

    try:
        resp = requests.post(SMARTAPI_LOGIN_BY_PASSWORD, json=payload, headers=headers, timeout=15)
    except Exception as e:
        raise Exception(f"SmartAPI login request failed: {e}")

    try:
        j = resp.json()
    except Exception:
        raise Exception(f"SmartAPI login: invalid JSON response ({resp.status_code}) - {resp.text[:300]}")

    # SmartAPI success shape typically: {"status": True, "message": "...", "data": {...}}
    if resp.status_code in (200, 201) and (j.get("status") is True or j.get("data")):
        data = j.get("data") or j
        tokens = {
            "jwtToken": data.get("jwtToken") or data.get("data", {}).get("jwtToken"),
            "refreshToken": data.get("refreshToken") or data.get("data", {}).get("refreshToken"),
            "feedToken": data.get("feedToken") or data.get("data", {}).get("feedToken"),
        }
        return {"raw": j, "tokens": tokens, "data": data}
    else:
        msg = j.get("message") if isinstance(j, dict) else str(j)
        raise Exception(f"SmartAPI login failed ({resp.status_code}): {msg}")


def smartapi_get_profile(jwt_token: str, client_code: str):
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
        "X-SourceID": "WEB",
        "X-ClientCode": client_code
    }
    try:
        resp = requests.get(SMARTAPI_GET_PROFILE, headers=headers, timeout=10)
    except Exception as e:
        raise Exception(f"SmartAPI getProfile request failed: {e}")

    try:
        j = resp.json()
    except Exception:
        raise Exception(f"SmartAPI getProfile: invalid JSON ({resp.status_code}) - {resp.text[:300]}")

    if resp.status_code == 200 and (j.get("status") is True or j.get("data") or j.get("clientcode")):
        return j
    else:
        msg = j.get("message") if isinstance(j, dict) else str(j)
        raise Exception(f"SmartAPI getProfile failed ({resp.status_code}): {msg}")


def verify_zerodha(api_key: str, access_token: str):
    """
    Verify Zerodha Kite connection by calling user profile.
    Kite Connect expects Authorization header as: token <api_key>:<access_token>
    """
    headers = {"Authorization": f"token {api_key}:{access_token}"}
    try:
        resp = requests.get(f"{ZERODHA_API_BASE}/user/profile", headers=headers, timeout=10)
    except Exception as e:
        raise Exception(f"Zerodha verify request failed: {e}")

    if resp.status_code == 200:
        try:
            j = resp.json()
        except Exception:
            raise Exception("Zerodha returned invalid JSON")
        return {"ok": True, "profile": j}
    else:
        raise Exception(f"Zerodha verify failed ({resp.status_code}): {resp.text[:300]}")


def verify_dhan(access_token: str):
    """
    Verify Dhan account. Endpoint may vary depending on Dhan's API version.
    Adjust endpoint to exact Dhan Connect endpoint.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    candidates = [
        f"{DHAN_API_BASE}/v1/accounts/details",
        f"{DHAN_API_BASE}/accounts/details",
        f"{DHAN_API_BASE}/v1/user/profile",
        f"{DHAN_API_BASE}/user/profile"
    ]
    for url in candidates:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except Exception:
            continue
        if resp.status_code == 200:
            try:
                return {"ok": True, "profile": resp.json()}
            except Exception:
                return {"ok": True, "profile": {"raw": resp.text}}
    raise Exception("Dhan verify failed: no valid profile endpoint response (check Dhan API base/paths and token).")


def verify_upstox(access_token: str):
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    try:
        resp = requests.get(f"{UPSTOX_API_BASE}/user/profile", headers=headers, timeout=10)
    except Exception as e:
        raise Exception(f"Upstox verify request failed: {e}")

    if resp.status_code == 200:
        try:
            j = resp.json()
        except Exception:
            raise Exception("Upstox returned invalid JSON")
        return {"ok": True, "profile": j}
    else:
        raise Exception(f"Upstox verify failed ({resp.status_code}): {resp.text[:300]}")


# -------------------------
# Broker: Verify credentials (multi-broker)
# -------------------------
@app.route("/api/broker/verify", methods=["POST"])
@require_auth
def broker_verify():
    try:
        data = request.get_json(force=True) or {}
        broker_name = (data.get("broker") or "").strip().lower()
        access_token = data.get("access_token")
        api_key = data.get("api_key") or access_token
        api_secret = data.get("api_secret") or data.get("refresh_token")
        meta = data.get("meta", {}) or {}

        if not broker_name:
            return jsonify({"ok": False, "error": "broker is required"}), 400

        verified = False
        user_info = {}

        # ---------------- ANGELONE ----------------
        if broker_name in ("angelone", "angel", "angel broking", "angelbroking"):
            api_key_local = data.get("api_key") or data.get("private_key") or api_key
            client_code = data.get("client_code") or data.get("clientid") or data.get("client_id")
            mpin = data.get("mpin") or data.get("password") or data.get("mpin_password")
            totp = data.get("totp") or None

            if not api_key_local or not client_code or not mpin:
                return jsonify({"ok": False, "verified": False, "message": "api_key, client_code and mpin/password required for AngelOne"}), 400

            try:
                client_local_ip = _safe_get_meta(meta, "client_local_ip") or data.get("client_local_ip")
                client_public_ip = _safe_get_meta(meta, "client_public_ip") or data.get("client_public_ip")
                mac_address = _safe_get_meta(meta, "mac_address") or data.get("mac_address")

                login_res = smartapi_login(
                    api_key=api_key_local,
                    client_code=client_code,
                    mpin_or_password=mpin,
                    totp=totp,
                    client_local_ip=client_local_ip,
                    client_public_ip=client_public_ip,
                    mac_address=mac_address
                )
                tokens = login_res.get("tokens", {})
                profile = {}
                try:
                    if tokens.get("jwtToken"):
                        profile = smartapi_get_profile(tokens.get("jwtToken"), client_code)
                except Exception as e_profile:
                    logger.warning("AngelOne profile fetch failed after login: %s", e_profile)

                uid = request.user["uid"]
                save_broker_tokens_to_firestore(uid, "angelone", tokens, meta)

                verified = True
                user_info = {
                    "broker": "AngelOne",
                    "client_id": client_code,
                    "profile": profile
                }
            except Exception as e:
                logger.warning("AngelOne verify failed: %s", e)
                return jsonify({"ok": False, "verified": False, "broker": "angelone", "message": str(e)}), 401

        # ---------------- ZERODHA ----------------
        elif broker_name == "zerodha":
            api_key_local = data.get("api_key")
            access_token_local = data.get("access_token") or data.get("token") or api_secret

            if not api_key_local or not access_token_local:
                return jsonify({"ok": False, "verified": False, "message": "api_key and access_token required for Zerodha"}), 400

            try:
                result = verify_zerodha(api_key_local, access_token_local)
                uid = request.user["uid"]
                save_broker_tokens_to_firestore(uid, "zerodha", {"access_token": access_token_local}, meta)
                verified = True
                user_info = {
                    "broker": "Zerodha",
                    "client_id": (result.get("profile", {}).get("data", {}) or {}).get("user_id") or result.get("profile", {}).get("user_id"),
                    "profile": result.get("profile")
                }
            except Exception as e:
                logger.warning("Zerodha verify failed: %s", e)
                return jsonify({"ok": False, "verified": False, "broker": "zerodha", "message": str(e)}), 401

        # ---------------- DHAN ----------------
        elif broker_name == "dhan":
            access_token_local = data.get("access_token") or data.get("api_key") or api_secret
            if not access_token_local:
                return jsonify({"ok": False, "verified": False, "message": "access_token required for Dhan"}), 400
            try:
                result = verify_dhan(access_token_local)
                uid = request.user["uid"]
                save_broker_tokens_to_firestore(uid, "dhan", {"access_token": access_token_local}, meta)
                verified = True
                user_info = {
                    "broker": "Dhan",
                    "client_id": result.get("profile", {}).get("clientId") or result.get("profile", {}).get("id"),
                    "profile": result.get("profile")
                }
            except Exception as e:
                logger.warning("Dhan verify failed: %s", e)
                return jsonify({"ok": False, "verified": False, "broker": "dhan", "message": str(e)}), 401

        # ---------------- UPSTOX ----------------
        elif broker_name == "upstox":
            access_token_local = data.get("access_token") or data.get("token") or api_secret
            if not access_token_local:
                return jsonify({"ok": False, "verified": False, "message": "access_token required for Upstox"}), 400
            try:
                result = verify_upstox(access_token_local)
                uid = request.user["uid"]
                save_broker_tokens_to_firestore(uid, "upstox", {"access_token": access_token_local}, meta)
                verified = True
                user_info = {
                    "broker": "Upstox",
                    "client_id": (result.get("profile", {}).get("data", {}) or {}).get("client_id") or result.get("profile", {}).get("client_id"),
                    "profile": result.get("profile")
                }
            except Exception as e:
                logger.warning("Upstox verify failed: %s", e)
                return jsonify({"ok": False, "verified": False, "broker": "upstox", "message": str(e)}), 401

        else:
            return jsonify({"ok": False, "verified": False, "message": f"Unsupported broker: {broker_name}"}), 400

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
        meta = data.get("meta", {}) or {}

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
