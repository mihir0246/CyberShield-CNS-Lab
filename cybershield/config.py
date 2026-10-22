import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-security-lab-key-2026")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    if os.getenv("VERCEL"):
        SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:////tmp/cybershield.db")
        UPLOAD_FOLDER = Path("/tmp/uploads")
    else:
        SQLALCHEMY_DATABASE_URI = os.getenv(
            "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'cybershield.db'}"
        )
        UPLOAD_FOLDER = BASE_DIR / "instance" / "uploads"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {"pcap", "cap", "pcapng", "log", "txt", "xml"}
    
    # Authorized network scan targets (restricted to local lab scope by default)
    ALLOWED_SCAN_TARGETS = [
        target.strip()
        for target in os.getenv("ALLOWED_SCAN_TARGETS", "127.0.0.1,localhost,::1").split(",")
        if target.strip()
    ]
    
    # Subprocess timeouts (seconds)
    NMAP_TIMEOUT_SECONDS = int(os.getenv("NMAP_TIMEOUT_SECONDS", "45"))
    SNORT_TIMEOUT_SECONDS = int(os.getenv("SNORT_TIMEOUT_SECONDS", "30"))
    
    # Security session configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration with in-memory SQLite and CSRF disabled."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1")
