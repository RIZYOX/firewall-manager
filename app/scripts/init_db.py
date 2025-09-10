#!/usr/bin/env python3
"""
Script d'initialisation de la base de données
Crée l'utilisateur administrateur par défaut si nécessaire
"""
import sys
import logging
from pathlib import Path

# Ajout du répertoire parent au chemin pour les imports
sys.path.append(str(Path(__file__).parent.parent))

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash, verify_password

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db() -> None:
    """Initialise la base de données avec l'utilisateur admin par défaut"""
    db = SessionLocal()
    
    try:
        # Vérifier si l'utilisateur admin existe déjà
        admin = db.query(User).filter(User.username == "admin").first()
        
        if not admin:
            # Créer l'utilisateur admin par défaut
            admin_user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=get_password_hash("admin"),
                is_active=True,
                is_superuser=True,
                full_name="Administrateur"
            )
            db.add(admin_user)
            db.commit()
            logger.info("Utilisateur admin créé avec succès")
            print("\033[92m✓ Compte administrateur créé avec succès!\033[0m")
            print("\033[93m⚠️  IMPORTANT: Veuillez changer le mot de passe après votre première connexion!\033[0m")
            print("\033[94m🔑 Identifiants par défaut:")
            print("   - Utilisateur: admin")
            print("   - Mot de passe: admin\033[0m")
        else:
            logger.info("L'utilisateur admin existe déjà")
            print("\033[93mℹ️  L'utilisateur admin existe déjà dans la base de données\033[0m")
    
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
        print(f"\033[91m✗ Erreur lors de l'initialisation de la base de données: {e}\033[0m")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("\033[1m=== Initialisation de la base de données ===\033[0m")
    init_db()
