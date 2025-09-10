#!/usr/bin/env python3
"""
Script de configuration des clés API pour les services d'IA

Utilisation:
    sudo /opt/firewall-manager/venv/bin/python /opt/firewall-manager/app/scripts/configure_ai.py
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

def load_env_file():
    """Charge le fichier .env"""
    env_path = Path('/opt/firewall-manager/.env')
    if not env_path.exists():
        print("❌ Fichier .env introuvable. Assurez-vous que l'application est correctement installée.")
        sys.exit(1)
    
    load_dotenv(env_path)
    return env_path

def update_env_file(env_path, updates):
    """Met à jour le fichier .env avec les nouvelles valeurs"""
    # Lire le contenu actuel
    with open(env_path, 'r') as f:
        lines = f.readlines()
    
    # Mettre à jour les valeurs existantes
    env_vars = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                key = line.split('=')[0]
                env_vars[key] = line
            except IndexError:
                continue
    
    # Ajouter/mettre à jour les nouvelles valeurs
    for key, value in updates.items():
        env_vars[key] = f"{key}={value}"
    
    # Réécrire le fichier
    with open(env_path, 'w') as f:
        for line in lines:
            if line.strip() and not line.strip().startswith('#') and '=' in line:
                key = line.split('=')[0].strip()
                if key in updates:
                    f.write(f"{key}={updates[key]}\n")
                else:
                    f.write(line)
            else:
                f.write(line)

def configure_openai():
    """Configure les clés API OpenAI"""
    print("\n🔑 Configuration d'OpenAI (ChatGPT)")
    print("Laissez vide pour conserver la valeur actuelle.")
    
    api_key = input("Clé API OpenAI (commence par 'sk-'): ").strip()
    org_id = input("ID d'organisation (optionnel): ").strip()
    
    updates = {}
    if api_key:
        updates['OPENAI_API_KEY'] = api_key
    if org_id:
        updates['OPENAI_ORGANIZATION'] = org_id
    
    return updates

def configure_google_ai():
    """Configure les identifiants Google Cloud AI"""
    print("\n🤖 Configuration de Google Cloud AI")
    print("Laissez vide pour conserver la valeur actuelle.")
    
    creds_path = input("Chemin vers le fichier de credentials JSON: ").strip()
    
    updates = {}
    if creds_path:
        updates['GOOGLE_APPLICATION_CREDENTIALS'] = creds_path
        
        # Vérifier que le fichier existe
        if not Path(creds_path).exists():
            print(f"⚠️  Attention: Le fichier {creds_path} n'existe pas. Assurez-vous de fournir le bon chemin.")
    
    return updates

def configure_azure_ai():
    """Configure les identifiants Azure AI"""
    print("\n🔷 Configuration d'Azure AI")
    print("Laissez vide pour conserver les valeurs actuelles.")
    
    api_key = input("Clé API Azure OpenAI: ").strip()
    endpoint = input("Point de terminaison (URL complète): ").strip()
    
    updates = {}
    if api_key:
        updates['AZURE_OPENAI_API_KEY'] = api_key
    if endpoint:
        updates['AZURE_OPENAI_ENDPOINT'] = endpoint
    
    return updates

def configure_huggingface():
    """Configure le token Hugging Face"""
    print("\n🤗 Configuration de Hugging Face")
    print("Laissez vide pour conserver la valeur actuelle.")
    
    token = input("Token d'API Hugging Face (commence par 'hf_'): ").strip()
    
    if token:
        return {'HUGGINGFACEHUB_API_TOKEN': token}
    return {}

def configure_anthropic():
    """Configure la clé API Anthropic (Claude)"""
    print("\n🧠 Configuration d'Anthropic (Claude)")
    print("Laissez vide pour conserver la valeur actuelle.")
    
    api_key = input("Clé API Anthropic (commence par 'sk-ant-'): ").strip()
    
    if api_key:
        return {'ANTHROPIC_API_KEY': api_key}
    return {}

def main():
    """Fonction principale"""
    # Vérifier les droits root
    if os.geteuid() != 0:
        print("❌ Ce script doit être exécuté en tant que root (utilisez sudo)")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("🛠️  Configuration des services d'IA")
    print("="*60)
    
    # Charger le fichier .env
    env_path = load_env_file()
    
    # Afficher le menu
    print("\nSélectionnez le service à configurer :")
    print("1. OpenAI (ChatGPT)")
    print("2. Google Cloud AI")
    print("3. Microsoft Azure AI")
    print("4. Hugging Face")
    print("5. Anthropic (Claude)")
    print("6. Tous les services")
    print("0. Quitter")
    
    choice = input("\nVotre choix [0-6]: ").strip()
    
    updates = {}
    
    if choice == '1':
        updates.update(configure_openai())
    elif choice == '2':
        updates.update(configure_google_ai())
    elif choice == '3':
        updates.update(configure_azure_ai())
    elif choice == '4':
        updates.update(configure_huggingface())
    elif choice == '5':
        updates.update(configure_anthropic())
    elif choice == '6':
        updates.update(configure_openai())
        updates.update(configure_google_ai())
        updates.update(configure_azure_ai())
        updates.update(configure_huggingface())
        updates.update(configure_anthropic())
    else:
        print("\nConfiguration annulée.")
        sys.exit(0)
    
    if updates:
        update_env_file(env_path, updates)
        print("\n✅ Configuration mise à jour avec succès!")
        print("\nPour appliquer les changements, redémarrez le service avec :")
        print("  sudo systemctl restart firewall-manager")
    else:
        print("\nAucune modification apportée.")

if __name__ == "__main__":
    main()
