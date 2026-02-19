from flask import Flask
from config import Config
from models import db
from flask import request, jsonify
from werkzeug.security import generate_password_hash
from models import User

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

    @app.get("/health") #if it returns 200, the system is awake
    def health():
        return jsonify({ok:True}),200

if __name__ == "__main__":
    app.run(debug=True)