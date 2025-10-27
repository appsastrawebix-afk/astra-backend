# app.py — Astra MarketMind unified production-ready backend
# Firestore + Realtime DB sync, AngelOne SmartAPI + TOTP, Zerodha/Upstox/Dhan verify
import os
import json
import logging
import datetime
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore, db as rtdb
from cryptography.fernet import Fernet, InvalidToken

# -------------------------
# Basic config
# -------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("astra-backend")

app = Flask(__name__)
CORS(app)

# -------------------------
# Environment variables (provide these in Render / env)
# -------------------------
FIREBASE_KEY = os.environ.get("FIREBASE_KEY")           # JSON string of service account
FERNET_KEY = os.environ.get("FERNET_KEY")               # base64 urlsafe key
ANGEL_API_KEY = os.environ.get("ANGEL_API_KEY", "").strip()
ANGEL_API_SECRET = os.environ.get("ANGEL_API_SECRET", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()  # e.g. https://...-default-rtdb.firebaseio.com

if not FIREBASE_KEY or not FERNET_KEY:
    raise Exception("FIREBASE_KEY and FERNET_KEY must be set in env")

# -------------------------
# Firebase initialization (Firestore + RTDB)
# -------------------------
try:
    firebase_dict = json.loads(FIREBASE_KEY)
    cred = credentials.Certificate(firebase_dict)
    if not firebase_admin._apps:
        # supply databaseURL only if provided (RTDB)
        if DATABASE_URL:
            firebase_admin.initialize_app(cred, {"databaseURL": DATABASE_URL})
        else:
            firebase_admin.initialize_app(cred)
    db_firestore = firestore.client()
    logger.info("Firebase initialized (Firestore%s)." % (" + RTDB" if DATABASE_URL else ""))
except Exception as e:
    logger.exception("Firebase init failed")
    raise

# -------------------------
# Fernet
# -------------------------
try:
    if isinstance(FERNET_KEY, str):
        fernet = Fernet(FERNET_KEY.encode())
    else:
        fernet = Fernet(FERNET_KEY)
except Exception:
    logger.exception("Invalid FERNET_KEY")
    raise

def encrypt_text(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode() if plain else ""

def decrypt_text(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        logger.warning("Invalid token decrypt")
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
# Health
# -------------------------
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "message": "Backend Connected Successfully!", "time": datetime.datetime.utcnow().isoformat()}), 200

# -------------------------
# Signup & login helpers
# -------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        display_name = data.get("displayName", "")
        if not email or not password:
            return jsonify({"ok": False, "error": "Email & password required"}), 400
        user = auth.create_user(email=email, password=password, display_name=display_name)
        db_firestore.collection("users").document(user.uid).set({
            "email": email,
            "displayName": display_name,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "brokers": {},
            "trading_accounts": {}
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
        return jsonify({"ok": True, "uid": decoded.get("uid"), "email": decoded.get("email"), "message": "Login successful"}), 200
    except Exception as e:
        logger.exception("Login failed")
        return jsonify({"ok": False, "error": str(e)}), 401

# -------------------------
# Save broker tokens (Firestore encrypted) + RTDB meta (non-sensitive)
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
        if tokens.get("access_token"):
            enc["access_token"] = encrypt_text(tokens["access_token"])
        if tokens.get("refresh_token"):
            enc["refresh_token"] = encrypt_text(tokens["refresh_token"])

        broker_doc = { **enc, "meta": meta or {}, "connected_at": datetime.datetime.utcnow().isoformat() }
        db_firestore.collection("users").document(uid).set({"brokers": {broker: broker_doc}}, merge=True)
        logger.info("Saved encrypted broker tokens in Firestore for %s/%s" % (uid, broker))

        # Also write safe meta to RTDB for mobile read (don't store secrets there)
        if DATABASE_URL:
            try:
                rtdb.reference(f"Users/{uid}/brokers/{broker}").set({
                    "meta": broker_doc.get("meta", {}),
                    "connected_at": broker_doc.get("connected_at")
                })
            except Exception:
                logger.exception("Failed writing broker meta to RTDB")
    except Exception:
        logger.exception("save_broker_tokens failed")

# -------------------------
# AngelOne SmartAPI login (loginByPassword)
# -------------------------
SMARTAPI_LOGIN_URL = "https://apiconnect.angelbroking.com/rest/auth/angelbroking/user/v1/loginByPassword"
SMARTAPI_GET_PROFILE = "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"

@app.route("/api/broker/angelone/login_by_password", methods=["POST"])
@require_auth
def angelone_login_by_password():
    try:
        # safe JSON parse
        try:
            body = request.get_json(force=True)
        except Exception:
            raw = request.data.decode("utf-8", errors="ignore")
            body = json.loads(raw) if raw else {}

        api_key = body.get("api_key") or ANGEL_API_KEY
        client_code = body.get("client_code") or body.get("client_id") or body.get("clientcode")
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

        logger.info("Calling SmartAPI login for client %s" % client_code)
        try:
            resp = requests.post(SMARTAPI_LOGIN_URL, json=payload, headers=headers, timeout=20)
        except Exception as e:
            logger.exception("SmartAPI request failed")
            return jsonify({"ok": False, "error": "SmartAPI request failed", "detail": str(e)}), 502

        logger.info("SmartAPI status %s" % resp.status_code)
        try:
            j = resp.json()
        except Exception:
            logger.warning("SmartAPI returned non-json")
            return jsonify({"ok": False, "error": "Invalid JSON from SmartAPI", "raw": resp.text[:400]}), 502

        # SmartAPI uses { status: true/false, data: {...} } pattern
        if resp.status_code in (200,201) and j.get("status") in (True, "true", "TRUE"):
            data = j.get("data", {})
            tokens = {
                "jwtToken": data.get("jwtToken"),
                "refreshToken": data.get("refreshToken"),
                "feedToken": data.get("feedToken"),
                "access_token": data.get("access_token")
            }

            uid = request.user["uid"]
            meta = {"client_code": client_code, "verified_at": datetime.datetime.utcnow().isoformat()}
            save_broker_tokens(uid, "angelone", tokens, meta)

            # Also ensure a trading_accounts.real exists and update client_id / api_key there
            try:
                # Update Firestore encrypted api_key token and client_id
                existing = db_firestore.collection("users").document(uid).get()
                if existing.exists:
                    user_doc = existing.to_dict()
                    accounts = user_doc.get("trading_accounts", {})
                    real_acc = accounts.get("real", {})
                    # update fields we can
                    real_acc.update({
                        "broker_name": "angelone",
                        "client_id": client_code,
                        # do NOT store raw mpin; store api_key only if provided in env/body
                        "last_verified": datetime.datetime.utcnow().isoformat()
                    })
                    db_firestore.collection("users").document(uid).set({"trading_accounts": {"real": real_acc}}, merge=True)
                # RTDB meta also
                if DATABASE_URL:
                    rtdb.reference(f"Users/{uid}/brokerAccounts/real").update({
                        "client_id": client_code,
                        "broker_name": "angelone",
                        "last_verified": datetime.datetime.utcnow().isoformat()
                    })
            except Exception:
                logger.exception("Failed updating account meta after AngelOne login")

            # Get profile (best-effort)
            profile_json = {}
            try:
                prof_headers = {
                    "Authorization": f"Bearer {tokens.get('jwtToken')}",
                    "X-ClientCode": client_code,
                    "Accept": "application/json"
                }
                profile_resp = requests.get(SMARTAPI_GET_PROFILE, headers=prof_headers, timeout=10)
                profile_json = profile_resp.json() if profile_resp.status_code == 200 else {"error": profile_resp.text}
                # optionally sync margin/positions to Firestore + RTDB
                # Try to capture margin or account summary from profile_json if present
                try:
                    margin = profile_json.get("data", {}).get("collateral", None) or profile_json.get("collateral", None)
                    if margin is not None:
                        # update firestore & rtdb
                        db_firestore.collection("users").document(uid).set({
                            "trading_accounts": {
                                "real": {"margin_balance": margin}
                            }
                        }, merge=True)
                        if DATABASE_URL:
                            rtdb.reference(f"Users/{uid}/brokerAccounts/real/margin_balance").set(margin)
                except Exception:
                    pass
            except Exception as e:
                profile_json = {"error": str(e)}

            return jsonify({"ok": True, "verified": True, "broker": "angelone", "message": "AngelOne SmartAPI verified", "profile": profile_json}), 200
        else:
            return jsonify({"ok": False, "verified": False, "error": j.get("message") or "SmartAPI verification failed", "response": j}), 401

    except Exception as e:
        logger.exception("AngelOne login error")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# optional: fetch profile / refresh margin (explicit)
# -------------------------
@app.route("/api/broker/angelone/get_profile", methods=["POST"])
@require_auth
def angelone_get_profile():
    try:
        data = request.get_json(force=True)
        uid = request.user["uid"]
        client_code = data.get("client_code")
        # read tokens from firestore
        doc = db_firestore.collection("users").document(uid).get()
        if not doc.exists:
            return jsonify({"ok": False, "error": "User not found"}), 404
        user = doc.to_dict()
        brokers = user.get("brokers", {})
        ang = brokers.get("angelone", {})
        enc_token = ang.get("access_token") or ang.get("jwtToken") or ang.get("access_token")
        if not enc_token:
            return jsonify({"ok": False, "error": "AngelOne token not found. Login first."}), 400
        jwt = decrypt_text(enc_token)
        if not jwt:
            return jsonify({"ok": False, "error": "Could not decrypt token"}), 500

        prof_headers = {
            "Authorization": f"Bearer {jwt}",
            "X-ClientCode": client_code,
            "Accept": "application/json"
        }
        profile_resp = requests.get(SMARTAPI_GET_PROFILE, headers=prof_headers, timeout=10)
        if profile_resp.status_code != 200:
            return jsonify({"ok": False, "error": "Profile fetch failed", "status": profile_resp.status_code, "body": profile_resp.text}), 502
        profile_json = profile_resp.json()

        # Example: pull margin if available and update Firestore/RTDB
        try:
            margin = profile_json.get("data", {}).get("collateral") or profile_json.get("collateral")
            if margin is not None:
                db_firestore.collection("users").document(uid).set({"trading_accounts": {"real": {"margin_balance": margin}}}, merge=True)
                if DATABASE_URL:
                    rtdb.reference(f"Users/{uid}/brokerAccounts/real/margin_balance").set(margin)
        except Exception:
            logger.exception("Failed update margin")

        return jsonify({"ok": True, "profile": profile_json}), 200
    except Exception as e:
        logger.exception("angelone get_profile failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Broker verify (Zerodha / Upstox / Dhan)
# -------------------------
@app.route("/api/broker/verify", methods=["POST"])
@require_auth
def broker_verify():
    try:
        data = request.get_json(force=True)
        broker = (data.get("broker") or "").lower()
        uid = request.user["uid"]

        if broker == "zerodha":
            api_key = data.get("api_key")
            access_token = data.get("access_token")
            if not (api_key and access_token):
                return jsonify({"ok": False, "error": "api_key and access_token required"}), 400
            headers = {"Authorization": f"token {api_key}:{access_token}"}
            resp = requests.get("https://api.kite.trade/user/profile", headers=headers, timeout=10)
            if resp.status_code == 200:
                save_broker_tokens(uid, "zerodha", {"access_token": access_token}, {"verified": True})
                return jsonify({"ok": True, "broker": "zerodha", "message": "Zerodha verified", "profile": resp.json()}), 200
            return jsonify({"ok": False, "error": resp.text}), 401

        elif broker == "upstox":
            access_token = data.get("access_token")
            if not access_token:
                return jsonify({"ok": False, "error": "access_token required"}), 400
            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            resp = requests.get("https://api.upstox.com/v2/user/profile", headers=headers, timeout=10)
            if resp.status_code == 200:
                save_broker_tokens(uid, "upstox", {"access_token": access_token}, {"verified": True})
                return jsonify({"ok": True, "broker": "upstox", "message": "Upstox verified", "profile": resp.json()}), 200
            return jsonify({"ok": False, "error": resp.text}), 401

        elif broker == "dhan":
            access_token = data.get("access_token")
            if not access_token:
                return jsonify({"ok": False, "error": "access_token required"}), 400
            headers = {"Authorization": f"Bearer {access_token}"}
            resp = requests.get("https://api.dhan.co/accounts/details", headers=headers, timeout=10)
            if resp.status_code == 200:
                save_broker_tokens(uid, "dhan", {"access_token": access_token}, {"verified": True})
                return jsonify({"ok": True, "broker": "dhan", "message": "Dhan verified", "profile": resp.json()}), 200
            return jsonify({"ok": False, "error": resp.text}), 401

        else:
            return jsonify({"ok": False, "error": f"Unsupported broker: {broker}"}), 400
    except Exception as e:
        logger.exception("broker_verify failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Broker list / disconnect
# -------------------------
@app.route("/api/broker/list", methods=["GET"])
@require_auth
def broker_list():
    try:
        uid = request.user["uid"]
        doc = db_firestore.collection("users").document(uid).get()
        if not doc.exists:
            return jsonify({"ok": False, "error": "User not found"}), 404
        brokers = doc.to_dict().get("brokers", {})
        safe = {k: {"meta": v.get("meta"), "connected_at": v.get("connected_at")} for k, v in brokers.items()}
        return jsonify({"ok": True, "brokers": safe}), 200
    except Exception as e:
        logger.exception("broker_list failed")
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
        ref = db_firestore.collection("users").document(uid)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"ok": False, "error": "User not found"}), 404
        brokers = doc.to_dict().get("brokers", {})
        if broker.lower() in brokers:
            brokers.pop(broker.lower())
            ref.set({"brokers": brokers}, merge=True)
            # RTDB remove meta too
            if DATABASE_URL:
                try:
                    rtdb.reference(f"Users/{uid}/brokers/{broker.lower()}").delete()
                except Exception:
                    pass
            return jsonify({"ok": True, "message": f"{broker} disconnected"}), 200
        return jsonify({"ok": False, "error": "Broker not connected"}), 404
    except Exception as e:
        logger.exception("broker_disconnect failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# User trading accounts (add/get) — Firestore only (saves RTDB for mobile if DB url present)
# -------------------------
@app.route("/api/user/add_trading_account", methods=["POST"])
@require_auth
def add_trading_account():
    try:
        try:
            raw_data = request.data.decode("utf-8")
            data = json.loads(raw_data) if raw_data else request.get_json(force=True)
        except Exception as e:
            logger.exception("JSON parse failed")
            return jsonify({"ok": False, "error": f"Invalid JSON: {str(e)}"}), 400

        uid = request.user["uid"]
        mode = data.get("mode", "real")
        if mode not in ["paper", "real"]:
            return jsonify({"ok": False, "error": "mode must be 'paper' or 'real'"}), 400

        if mode == "real":
            broker_name = data.get("broker_name")
            api_key = data.get("api_key")
            client_id = data.get("client_id")
            access_token = data.get("access_token", "")
            if not all([broker_name, api_key, client_id]):
                return jsonify({"ok": False, "error": "Missing broker_name, api_key, or client_id"}), 400
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

        db_firestore.collection("users").document(uid).set({"trading_accounts": {mode: account_data}}, merge=True)

        # RTDB sync (plain) for mobile app
        if DATABASE_URL:
            try:
                plain_for_rtdb = dict(account_data)
                # decrypt api_key & access_token before writing to RTDB (mobile expects readable)
                plain_for_rtdb["api_key"] = decrypt_text(plain_for_rtdb.get("api_key", "")) if mode == "real" else plain_for_rtdb.get("api_key")
                plain_for_rtdb["access_token"] = decrypt_text(plain_for_rtdb.get("access_token", "")) if mode == "real" else plain_for_rtdb.get("access_token")
                rtdb.reference(f"Users/{uid}/brokerAccounts/{mode}").set(plain_for_rtdb)
            except Exception:
                logger.exception("RTDB sync failed")

        logger.info("Trading account added for %s (%s)" % (uid, mode))
        return jsonify({"ok": True, "message": f"{mode.capitalize()} trading account added successfully!"}), 200
    except Exception as e:
        logger.exception("add_trading_account failed")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/user/get_trading_account", methods=["POST"])
@require_auth
def get_trading_account():
    try:
        data = request.get_json(force=True)
        uid = request.user["uid"]
        mode = data.get("mode", "real")

        doc = db_firestore.collection("users").document(uid).get()
        if not doc.exists:
            return jsonify({"ok": False, "error": "User not found"}), 404

        accounts = doc.to_dict().get("trading_accounts", {})
        acc = accounts.get(mode)
        if not acc:
            return jsonify({"ok": False, "error": f"No {mode} account found"}), 404

        if mode == "real":
            acc["api_key"] = decrypt_text(acc.get("api_key", ""))
            acc["access_token"] = decrypt_text(acc.get("access_token", ""))

        return jsonify({"ok": True, "mode": mode, "account": acc}), 200
    except Exception as e:
        logger.exception("get_trading_account failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Mode switch
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
        db_firestore.collection("users").document(uid).set({"mode": mode}, merge=True)
        return jsonify({"ok": True, "message": f"Mode switched to {mode}"}), 200
    except Exception as e:
        logger.exception("switch_mode failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Flask on port %s" % port)
    app.run(host="0.0.0.0", port=port)
