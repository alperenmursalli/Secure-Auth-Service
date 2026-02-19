import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # --- Secret Keys ---
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Redis ---
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB = int(os.getenv("REDIS_DB", "0"))

    # --- JWT Expiration ---
    ACCESS_EXPIRES_MIN = int(os.getenv("ACCESS_EXPIRES_MIN", "15"))
    REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "14"))

    # --- Rate Limiting ---
    LOGIN_LIMIT = int(os.getenv("LOGIN_LIMIT", "5"))
    LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "60"))

    # --- Account Lock ---
    FAIL_LIMIT = int(os.getenv("FAIL_LIMIT", "5"))
    LOCK_SECONDS = int(os.getenv("LOCK_SECONDS", "600"))
