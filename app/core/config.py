"""
Configuration de l'application
"""
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import AnyHttpUrl, BaseSettings, EmailStr, HttpUrl, PostgresDsn, validator

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Firewall Manager"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_urlsafe(32)
    
    # API
    API_PREFIX: str = "/api"
    API_VERSION: str = "v1"
    
    # Security
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    ALGORITHM: str = "HS256"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost",
        "http://localhost:8000",
        "http://localhost:3000",
    ]
    
    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "firewall"
    SQLALCHEMY_DATABASE_URI: Optional[PostgresDsn] = None
    
    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )
    
    # Email
    SMTP_TLS: bool = True
    SMTP_PORT: Optional[int] = None
    SMTP_HOST: Optional[str] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None
    EMAILS_FROM_NAME: Optional[str] = None
    
    @validator("EMAILS_FROM_NAME")
    def get_project_name(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if not v:
            return values["APP_NAME"]
        return v
    
    # First admin user
    FIRST_SUPERUSER_EMAIL: EmailStr = "admin@example.com"
    FIRST_SUPERUSER_USERNAME: str = "admin"
    FIRST_SUPERUSER_PASSWORD: str = "admin"
    
    # Firewall
    FIREWALL_SERVICE: str = "ufw"  # ufw, iptables, firewalld
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    UPLOAD_FOLDER: Path = BASE_DIR / "uploads"
    BACKUP_FOLDER: Path = BASE_DIR / "backups"
    LOG_FOLDER: Path = BASE_DIR / "logs"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = str(LOG_FOLDER / "firewall.log")
    
    # Rate limiting
    RATE_LIMIT: str = "100/minute"
    
    # Session
    SESSION_SECRET: str = secrets.token_urlsafe(32)
    SESSION_LIFETIME: int = 86400  # 24 hours in seconds
    
    # File uploads
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS: List[str] = ["txt", "pdf", "png", "jpg", "jpeg", "gif", "zip", "json"]
    
    # Backups
    MAX_BACKUPS: int = 10
    
    # Monitoring
    MONITORING_ENABLED: bool = True
    MONITORING_INTERVAL: int = 60  # seconds
    
    # Updates
    CHECK_FOR_UPDATES: bool = True
    UPDATE_CHECK_INTERVAL: int = 86400  # 24 hours in seconds
    
    class Config:
        case_sensitive = True
        env_file = ".env"

# Chargement des variables d'environnement
settings = Settings()

# Création des dossiers nécessaires
for folder in [settings.UPLOAD_FOLDER, settings.BACKUP_FOLDER, settings.LOG_FOLDER]:
    folder.mkdir(exist_ok=True, parents=True)
