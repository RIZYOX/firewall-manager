#!/usr/bin/env python3
"""
Script de création d'utilisateur pour Firewall Manager

Utilisation:
    sudo /opt/firewall-manager/venv/bin/python /opt/firewall-manager/app/scripts/create_user.py
"""
import getpass
import sys
from pathlib import Path

# Ajout du répertoire parent au chemin pour les imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

def create_admin_user():
    """Crée un nouvel utilisateur administrateur"""
    print("\n=== Création d'un nouvel utilisateur administrateur ===\n")
    
    # Demander les informations de l'utilisateur
    username = input("Nom d'utilisateur: ")
    email = input("Adresse email: ")
    
    while True:
        password = getpass.getpass("Mot de passe (minimum 12 caractères): ")
        if len(password) < 12:
            print("Le mot de passe doit contenir au moins 12 caractères.")
            continue
            
        confirm_password = getpass.getpass("Confirmer le mot de passe: ")
        if password != confirm_password:
            print("Les mots de passe ne correspondent pas. Veuillez réessayer.")
        else:
            break
    
    # Créer l'utilisateur dans la base de données
    db = SessionLocal()
    try:
        # Vérifier si l'utilisateur existe déjà
        if db.query(User).filter(User.username == username).first():
            print(f"\n❌ L'utilisateur '{username}' existe déjà.")
            return
        
        # Créer le nouvel utilisateur
        user = User(
            username=username,
            email=email,
            hashed_password=get_password_hash(password),
            is_active=True,
            is_superuser=True,
            full_name=username
        )
        
        db.add(user)
        db.commit()
        
        print(f"\n✅ Utilisateur '{username}' créé avec succès !")
        print("\nVous pouvez maintenant vous connecter à l'interface d'administration.")
        
    except Exception as e:
        print(f"\n❌ Erreur lors de la création de l'utilisateur: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    # Vérifier les droits root
    import os
    if os.geteuid() != 0:
        print("❌ Ce script doit être exécuté en tant que root (utilisez sudo)")
        sys.exit(1)
    
    create_admin_user()
