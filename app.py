from flask import Flask
from config import Config
from models import db
from flask import request, jsonify
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from models import User
import redis

r = redis.Redis(
    host=app.config["REDIS_HOST"],
    port=app.config["REDIS_PORT"],
    db=0,
    decode_responses=True
)

app=Flask(__name__)
app.config.from_object(Config) #Config -> app.config

db.init_app(app) #connected to Flask

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return "Auth Service Running"

@app.route("/auth/register")
def register():
    data = request.get_json(silent=True) or {} #if no JSOn , it will not crash

    email = data.get("email")
    password = data.get("password")

    email=(data.get("email") or "").strip().lower()
    password=(data.get("password") or"")


    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if len(password)<8:
        return jsonify({"error": "password must be at least 8 characters"})
    if len(password)>128:
        return jsonify({"error":"password is too long. Password can be at maxiumum 128 characters in length"})

    #uniqueness
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error":"email already exists"}),409

    password_hash= generate_password_hash(password)

    user= User(email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({"ok":True,
                    "message":"registered"}),201

    @app.get("/health") #if it returns 200, the system is healthy
    def health():
        return jsonify({ok:True}),200
    

FAKE_HASH = generate_password_hash("fake-password") #for timing attack security

@app.post("/auth/login")
def login():


    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    password= (data.get("password") or "")

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    email_key=f"login:email:{email}"
    email_attempts = r.get(email_key)

    if email_attempts and int(email_attempts) >= 5:
        return jsonify({"error": "account temporarily locked"}), 403

    ip = request.remote_addr
    key = f"login:ip:{ip}"
    attempts = r.incr(key)

    if attempts == 1:
        r.expire(key,60)

    if attempts > 5:
        return jsonify({"error": "too many attempts"}), 429

    #fake hash for timing attack   
    existing = User.query.filter_by(email=email).first()

    if existing:
        password_ok=check_password_hash(existing.password_hash,password)
    else:
        check_password_hash(FAKE_HASH,password)
        password_ok = False 

    if not password_ok:
        return jsonify({"error":"invalid credentials"}),401
    
    """if not existing or not check_password_hash(existing.password_hash, password):
        fail_count = r.incr(email_key)
        if fail_count == 1:
            r.expire(email_key,600) #10 minute lock window    
        return jsonify({"error": "invalid credentials"}), 401"""
    r.delete(email_key)

    return jsonify({"message":"login successful"}),200






if __name__ == "__main__":
    app.run(debug=True)