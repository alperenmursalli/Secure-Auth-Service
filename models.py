from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__="users"

    id=db.Column(db.Integer, primary_key=True)

    email=db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True)
    
    password_hash=db.Column(
        db.String(255),
        nullable=False
    )

    locked_until = db.Column(
        db.DateTime,
        nullable=True
    )

    created_at=db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    token_version = db.Column(
        db.Integer, default=0
        )
