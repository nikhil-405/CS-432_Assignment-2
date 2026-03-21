import os
from pathlib import Path
from urllib.parse import quote_plus

BASE_DIR = Path(__file__).resolve().parent


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Config:
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = _int_env("DB_PORT", 3306)
    DB_NAME = os.getenv("DB_NAME", "SafeDocs")

    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-me-for-production")
    JWT_SECRET = os.getenv("JWT_SECRET", "change-me-jwt-secret")
    JWT_ALGORITHM = "HS256"
    SESSION_TTL_MINUTES = _int_env("SESSION_TTL_MINUTES", 120)

    DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", str(BASE_DIR / "logs" / "audit.log"))

    @classmethod
    def database_url(cls) -> str:
        quoted_password = quote_plus(cls.DB_PASSWORD)
        return (
            f"mysql+pymysql://{cls.DB_USER}:{quoted_password}@"
            f"{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
        )
