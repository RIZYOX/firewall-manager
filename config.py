"""
Configuration du Firewall Simple
"""
import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Paramètres de l'application
    APP_NAME: str = "Firewall Simple"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Base de données
    DATABASE_URL: str = "sqlite:///./firewall.db"
    
    # Sécurité
    SECRET_KEY: str = "votre_cle_secrete_tres_longue_et_securisee"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 jours
    
    # Paramètres réseau
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Règles par défaut
    DEFAULT_RULES = [
        {
            "name": "Allow SSH",
            "action": "allow",
            "protocol": "tcp",
            "port": 22,
            "source": "any",
            "description": "Accès SSH"
        },
        {
            "name": "Allow HTTP",
            "action": "allow",
            "protocol": "tcp",
            "port": 80,
            "source": "any",
            "description": "Accès HTTP"
        },
        {
            "name": "Allow HTTPS",
            "action": "allow",
            "protocol": "tcp",
            "port": 443,
            "source": "any",
            "description": "Accès HTTPS"
        },
        {
            "name": "Block All",
            "action": "deny",
            "protocol": "any",
            "port": 0,
            "source": "any",
            "description": "Règle de blocage par défaut"
        }
    ]

# Instance des paramètres
settings = Settings()
