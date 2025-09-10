# 🛡️ Firewall Manager

Un pare-feu professionnel avec interface web intuitive, conçu pour une installation et une utilisation faciles. Générez et gérez vos règles de pare-feu en quelques clics.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## ✨ Fonctionnalités

- 🚀 **Installation en une commande** - Script d'installation automatisé
- 🔒 **Sécurité renforcée** - Authentification 2FA, protection CSRF, limitation de débit
- 📊 **Tableau de bord complet** - Visualisation en temps réel du trafic et des événements
- 🛠️ **Gestion simplifiée** - Interface intuitive pour gérer les règles de pare-feu
- 🔄 **Sauvegardes automatiques** - Sauvegarde et restauration des configurations
- 📱 **100% Responsive** - Accessible depuis n'importe quel appareil
- 🔔 **Notifications** - Alertes en temps réel pour les événements critiques

## 🚀 Installation rapide (1 minute)

### Prérequis
- Système d'exploitation : **Ubuntu 20.04/22.04** (recommandé) ou autre distribution Linux
- Droits **root** pour l'installation
- Connexion Internet

### Installation en une commande

```bash
# Télécharger le script d'installation
curl -sSL https://raw.githubusercontent.com/votre-utilisateur/firewall-manager/main/install.sh | sudo bash
```

Ou si vous avez déjà cloné le dépôt :

```bash
# Rendre le script exécutable
chmod +x install.sh

# Lancer l'installation
sudo ./install.sh
```

### Accès après installation

Une fois l'installation terminée, accédez à l'interface :
- **Interface web** : `http://votre-ip`
- **Documentation API** : `http://votre-ip/docs`

🔑 **Identifiants par défaut** :
- **Utilisateur** : admin
- **Mot de passe** : admin (à changer immédiatement)

## 🔧 Configuration avancée

### Fichier de configuration principal
```bash
nano /etc/firewall-manager/.env
```

### Gestion du service
```bash
# Démarrer le service
sudo systemctl start firewall-manager

# Arrêter le service
sudo systemctl stop firewall-manager

# Voir les logs
sudo journalctl -u firewall-manager -f
```

### Mise à jour SSL (Recommandé)
```bash
sudo certbot --nginx -d votre-domaine.com
```

## Configuration

Copiez le fichier `.env.example` vers `.env` et modifiez les variables selon vos besoins :

```env
# Application
APP_NAME="Firewall Manager"
DEBUG=True
SECRET_KEY=votre_cle_secrete_tres_longue_et_securisee

# Base de données
DATABASE_URL=sqlite:///./firewall.db
# Pour PostgreSQL :
# DATABASE_URL=postgresql://user:password@localhost/firewall

# Sécurité
ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 heures
ALGORITHM=HS256

# Paramètres réseau
HOST=0.0.0.0
PORT=8000

# Paramètres du pare-feu
FIREWALL_SERVICE=ufw  # ufw, iptables, firewalld
```

## Utilisation

### Ligne de commande

```bash
# Lancer le serveur de développement
uvicorn app.main:app --reload

# Lancer en production avec Gunicorn (recommandé)
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app

# Appliquer les migrations de base de données
alembic upgrade head
```

### API

L'API est documentée avec OpenAPI et disponible à l'adresse `/api/docs` ou `/api/redoc`.

Exemple avec cURL :

```bash
# Obtenir un token d'authentification
curl -X 'POST' \
  'http://localhost:8000/api/auth/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=admin'

# Lister les règles
curl -X 'GET' \
  'http://localhost:8000/api/rules/' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer VOTRE_TOKEN_JWT'
```

## Déploiement

### Avec Docker (recommandé)

```bash
# Construire l'image
docker build -t firewall-manager .

# Lancer le conteneur
docker run -d --name firewall-manager \
  -p 8000:8000 \
  --restart unless-stopped \
  -v $(pwd)/data:/app/data \
  -e DATABASE_URL=sqlite:////app/data/firewall.db \
  firewall-manager
```

### Avec systemd

Créez un fichier `/etc/systemd/system/firewall-manager.service` :

```ini
[Unit]
Description=Firewall Manager
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/chemin/vers/firewall-manager
Environment="PATH=/chemin/vers/venv/bin"
ExecStart=/chemin/vers/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Puis activez et démarrez le service :

```bash
sudo systemctl enable firewall-manager
sudo systemctl start firewall-manager
```

## Sécurité

- Changez le mot de passe admin par défaut après la première connexion
- Utilisez toujours HTTPS en production
- Limitez l'accès à l'interface d'administration
- Mettez à jour régulièrement les dépendances
- Ne stockez pas de données sensibles dans le code source

## Structure du projet

```
firewall-manager/
├── app/                    # Code source de l'application
│   ├── api/                # Points de terminaison de l'API
│   ├── core/               # Configuration et logique métier
│   ├── db/                 # Configuration de la base de données
│   ├── models/             # Modèles SQLAlchemy
│   ├── schemas/            # Schémas Pydantic
│   ├── static/             # Fichiers statiques (JS, CSS, images)
│   ├── templates/          # Templates HTML
│   └── utils/              # Utilitaires
├── migrations/             # Migrations Alembic
├── tests/                  # Tests automatisés
├── .env.example            # Exemple de fichier d'environnement
├── .gitignore
├── alembic.ini             # Configuration Alembic
├── main.py                 # Point d'entrée de l'application
└── requirements.txt        # Dépendances
```

## Contribuer

1. Forkez le projet
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/ma-fonctionnalite`)
3. Committez vos modifications (`git commit -am 'Ajouter une fonctionnalité'`)
4. Poussez vers la branche (`git push origin feature/ma-fonctionnalite`)
5. Ouvrez une Pull Request

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Support

Pour toute question ou problème, veuillez ouvrir une issue sur GitHub.
