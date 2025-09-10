#!/usr/bin/env python3
"""
Script de post-installation
Effectue les configurations finales après l'installation
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(cmd: str) -> tuple[bool, str]:
    """Exécute une commande shell et retourne le résultat"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, f"{e.stderr}\n{e.stdout}"

def setup_firewall() -> bool:
    """Configure le pare-feu UFW"""
    print("\n🛡️  Configuration du pare-feu UFW...")
    
    # Activer UFW s'il n'est pas déjà actif
    success, output = run_command("ufw status | grep -q 'Status: active' || ufw --force enable")
    if not success:
        print(f"❌ Erreur lors de l'activation d'UFW: {output}")
        return False
    
    # Configurer les règles de base
    rules = [
        "ufw allow 'Nginx Full'",
        "ufw allow 'OpenSSH'",
        "ufw limit ssh"  # Protection contre les attaques par force brute
    ]
    
    for rule in rules:
        success, output = run_command(rule)
        if not success and "Skipping" not in output:  # Ignorer si la règle existe déjà
            print(f"⚠️  Avertissement lors de la configuration d'UFW: {output}")
    
    print("✅ Configuration du pare-feu terminée")
    return True

def setup_ssl() -> None:
    """Propose la configuration SSL avec Let's Encrypt"""
    print("\n🔐 Configuration SSL avec Let's Encrypt")
    
    # Vérifier si certbot est installé
    if not shutil.which("certbot"):
        print("ℹ️  Installation de Certbot pour Let's Encrypt...")
        success, output = run_command("apt-get install -y certbot python3-certbot-nginx")
        if not success:
            print(f"⚠️  Impossible d'installer Certbot: {output}")
            return
    
    # Demander le nom de domaine
    domain = input("\nEntrez votre nom de domaine (ou laissez vide pour ignorer pour l'instant): ").strip()
    
    if domain:
        print(f"\nConfiguration de SSL pour {domain}...")
        success, output = run_command(f"certbot --nginx -d {domain} --non-interactive --agree-tos --email admin@{domain} --redirect")
        
        if success:
            print("✅ Configuration SSL réussie!")
            print(f"Votre application est maintenant accessible en toute sécurité sur https://{domain}")
        else:
            print(f"⚠️  Échec de la configuration SSL: {output}")
            print("Vous pouvez configurer manuellement SSL plus tard avec la commande:")
            print("sudo certbot --nginx -d votre-domaine.com")
    else:
        print("ℹ️  Configuration SSL ignorée. Vous pourrez la configurer plus tard avec:")
        print("sudo certbot --nginx -d votre-domaine.com")

def setup_admin_password() -> None:
    """Propose de changer le mot de passe admin par défaut"""
    print("\n🔑 Configuration du mot de passe administrateur")
    print("ℹ️  Le mot de passe par défaut est 'admin'. Il est fortement recommandé de le changer.")
    
    change = input("Voulez-vous changer le mot de passe admin maintenant ? (O/n): ").strip().lower()
    
    if change in ('', 'o', 'oui', 'y', 'yes'):
        from app.db.session import SessionLocal
        from app.models.user import User
        from app.core.security import get_password_hash
        
        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.username == "admin").first()
            if not admin:
                print("⚠️  Utilisateur admin introuvable")
                return
                
            while True:
                password = input("Nouveau mot de passe (minimum 12 caractères): ")
                if len(password) >= 12:
                    break
                print("❌ Le mot de passe doit contenir au moins 12 caractères")
            
            admin.hashed_password = get_password_hash(password)
            db.commit()
            print("✅ Mot de passe administrateur mis à jour avec succès!")
            
        except Exception as e:
            print(f"❌ Erreur lors de la mise à jour du mot de passe: {e}")
            db.rollback()
        finally:
            db.close()
    else:
        print("⚠️  N'oubliez pas de changer le mot de passe par défaut après l'installation!")

def check_requirements() -> bool:
    """Vérifie les dépendances système requises"""
    print("\n🔍 Vérification des dépendances système...")
    
    requirements = [
        ("python3", "Python 3.8+", "python3 --version"),
        ("pip3", "Pip", "pip3 --version"),
        ("nginx", "Nginx", "nginx -v"),
        ("ufw", "UFW", "ufw --version")
    ]
    
    all_ok = True
    for cmd, name, check_cmd in requirements:
        success, output = run_command(f"which {cmd}")
        if success:
            version = subprocess.getoutput(check_cmd).split('\n')[0]
            print(f"✅ {name}: {version}")
        else:
            print(f"❌ {name} n'est pas installé")
            all_ok = False
    
    return all_ok

def main():
    """Fonction principale"""
    print("\n" + "="*60)
    print("🛠️  Script de post-installation du Firewall Manager")
    print("="*60)
    
    # Vérifier les dépendances
    if not check_requirements():
        print("\n❌ Certaines dépendances sont manquantes. Veuillez les installer avant de continuer.")
        sys.exit(1)
    
    # Configurer le pare-feu
    setup_firewall()
    
    # Proposer la configuration SSL
    setup_ssl()
    
    # Proposer de changer le mot de passe admin
    setup_admin_password()
    
    # Redémarrer les services
    print("\n🔄 Redémarrage des services...")
    run_command("systemctl restart nginx")
    run_command("systemctl restart firewall-manager")
    
    # Afficher les informations de connexion
    ip_address = subprocess.getoutput("hostname -I | awk '{print $1}'")
    
    print("\n" + "="*60)
    print("🎉 Installation terminée avec succès!")
    print("="*60)
    print(f"\n🌐 Accès à l'interface web:")
    print(f"   - http://{ip_address}" if ip_address else "   - http://votre-ip")
    print("\n🔑 Identifiants par défaut:")
    print("   - Utilisateur: admin")
    print("   - Mot de passe: admin (ou celui que vous avez défini)")
    print("\n⚠️  Pour des raisons de sécurité, il est fortement recommandé de:") 
    print("   1. Changer le mot de passe par défaut")
    print("   2. Configurer un certificat SSL")
    print("   3. Mettre à jour régulièrement le système")
    print("\nPour plus d'informations, consultez la documentation à l'adresse:")
    print("https://github.com/votre-utilisateur/firewall-manager")
    print("\n" + "="*60)

if __name__ == "__main__":
    # Vérifier les droits root
    if os.geteuid() != 0:
        print("❌ Ce script doit être exécuté en tant que root (utilisez sudo)")
        sys.exit(1)
    
    main()
