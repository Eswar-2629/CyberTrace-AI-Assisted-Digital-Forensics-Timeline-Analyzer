import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]
    JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
    FERNET_KEY = os.environ["FERNET_KEY"]

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://cybertrace:change_me@localhost:5432/cybertrace"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
    )

    MAX_CONTENT_LENGTH = int(
        os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024))
    )

    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5000")