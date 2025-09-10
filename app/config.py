"""
Configuration de l'application
"""
import os
from pydantic import BaseSettings, AnyHttpUrl
from typing import List, Optional

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Firewall Manager"
    DEBUG: bool = True
    SECRET_KEY: str = "change-this-in-production"
    
    # Base de données
    DATABASE_URL: str = "sqlite:///./firewall.db"
    
    # Sécurité
    ALLOWED_ORIGINS: List[AnyHttpUrl] = ["http://localhost:8000"]
    
    # Paramètres réseau
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Paramètres du pare-feu
    FIREWALL_SERVICE: str = "ufw"  # ufw, iptables, firewalld
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Instance des paramètres
settings = Settings()
