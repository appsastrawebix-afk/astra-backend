from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
import datetime
import os
import json

# ✅ Initialize Flask
app = Flask(__name__)

# ✅ Initialize Firebase Securely from Environment Variable
if not firebase_admin._apps:
    firebase_key_json = os.environ.get("FIREBASE_KEY")
    if firebase_key_json:
        cred_dict = json.loads(firebase_key_json)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
    else:
        raise Exception("❌ FIREBASE_KEY environment variable not found. Please set it in Render.")

# ✅ Firestore Client
db = firestore.client()


# 🧩 TEST ROUTE — Backend check (for Android Retrofit)
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({
        "ok": True,
        "message": "Backend Connected Successfully!",
        "time": datetime.datetime.utcnow().isoformat()
    }), 200


# 🧠 SIGNUP ROUTE
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")
    display_name = data.get("displayName", "")

    if not email or not password:
        return jsonify({"error": "Email and Password required"}), 400

    try:
        # Firebase Auth - Create user
        user_record = auth.create_user(
            email=email,
            password=password,
            display_name=display_name
        )

        uid = user_record.uid

        # Firestore - Save user profile
        db.collection("users").document(uid).set({
            "email": email,
            "displayName": display_name,
            "createdAt": datetime.datetime.utcnow(),
            "role": "user",
            "mode": "paper",
            "preferences": {},
            "kyc_completed": False
        })

        return jsonify({"uid": uid, "message": "User created successfully!"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔑 LOGIN ROUTE
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    id_token = data.get("idToken")

    if not id_token:
        return jsonify({"error": "idToken required"}), 400

    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token["uid"]
        email = decoded_token.get("email")

        return jsonify({
            "uid": uid,
            "email": email,
            "message": "Login successful"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401


# 🚀 ENTRY POINT (Render Production Mode)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render automatically assigns this
    app.run(host="0.0.0.0", port=port)  # ⚠️ No debug mode in production
