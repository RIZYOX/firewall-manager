#!/bin/bash

# ===========================================
# Script d'installation Firewall Manager
# ===========================================

# Couleurs pour une meilleure lisibilité
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher un message d'erreur et quitter
function error_exit {
    echo -e "${RED}Erreur: $1${NC}" >&2
    exit 1
}

# Fonction pour vérifier la commande
function check_command {
    command -v $1 >/dev/null 2>&1 || error_exit "$1 n'est pas installé. Veuillez l'installer et réessayer."
}

# Vérification des droits root
if [ "$EUID" -ne 0 ]; then 
    error_exit "Ce script doit être exécuté en tant que root"
fi

# Vérification des commandes nécessaires
for cmd in python3 pip3 systemctl; do
    check_command $cmd
done

# Configuration
APP_NAME="Firewall Manager"
APP_USER="firewall"
APP_GROUP="firewall"
APP_DIR="/opt/firewall-manager"
VENV_DIR="$APP_DIR/venv"
LOG_DIR="/var/log/firewall-manager"
CONFIG_DIR="/etc/firewall-manager"
SERVICE_NAME="firewall-manager"

# Affichage du message de bienvenue
echo -e "${GREEN}=== Installation de $APP_NAME ===${NC}"
echo -e "${YELLOW}Ce script va installer et configurer $APP_NAME${NC}"
echo -e "${YELLOW}Assurez-vous d'avoir un accès Internet actif${NC}"
echo ""

# Demande de confirmation
read -p "Voulez-vous continuer l'installation ? (O/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
    echo -e "${YELLOW}Installation annulée par l'utilisateur.${NC}"
    exit 1
fi

# Mise à jour du système
echo -e "${BLUE}[1/8] Mise à jour du système...${NC}"
apt-get update && apt-get upgrade -y

# Installation des dépendances système
echo -e "${BLUE}[2/8] Installation des dépendances système...${NC}"
apt-get install -y \
    python3-pip \
    python3-venv \
    ufw \
    fail2ban \
    nginx \
    certbot \
    python3-certbot-nginx

# Création de l'utilisateur et des répertoires
echo -e "${BLUE}[3/8] Configuration des répertoires...${NC}"
if ! id -u $APP_USER >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin $APP_USER || error_exit "Échec de la création de l'utilisateur $APP_USER"
fi

mkdir -p $APP_DIR $LOG_DIR $CONFIG_DIR
chown -R $APP_USER:$APP_GROUP $APP_DIR $LOG_DIR $CONFIG_DIR
chmod 750 $APP_DIR $LOG_DIR $CONFIG_DIR

# Installation de l'application
echo -e "${BLUE}[4/8] Installation de l'application...${NC}"
cp -r . $APP_DIR/
chown -R $APP_USER:$APP_GROUP $APP_DIR
chmod -R 750 $APP_DIR

# Configuration de l'environnement virtuel
echo -e "${BLUE}[5/8] Configuration de l'environnement Python...${NC}
sudo -u $APP_USER python3 -m venv $VENV_DIR || error_exit "Échec de la création de l'environnement virtuel"

# Installation des dépendances Python
$VENV_DIR/bin/pip install --upgrade pip
$VENV_DIR/bin/pip install -r requirements.txt || error_exit "Échec de l'installation des dépendances Python"

# Configuration de l'application
echo -e "${BLUE}[6/8] Configuration de l'application...${NC}"
# Génération d'une clé secrète sécurisée
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Création du fichier de configuration
cat > $CONFIG_DIR/.env <<EOL
# Configuration de l'application
DEBUG=False
SECRET_KEY=$SECRET_KEY

# Base de données
DATABASE_URL=sqlite:///$APP_DIR/firewall.db

# Sécurité
ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 heures
ALGORITHM=HS256

# CORS
ALLOWED_ORIGINS=['http://localhost', 'http://localhost:8000']

# Chemins
UPLOAD_FOLDER=$APP_DIR/uploads
BACKUP_FOLDER=$APP_DIR/backups
LOG_FILE=$LOG_DIR/firewall.log

# Configuration du pare-feu
FIREWALL_SERVICE=ufw
EOL

# Configuration des permissions
chown $APP_USER:$APP_GROUP $CONFIG_DIR/.env
chmod 640 $CONFIG_DIR/.env

# Configuration du service systemd
echo -e "${BLUE}[7/8] Configuration du service systemd...${NC}"
cat > /etc/systemd/system/$SERVICE_NAME.service <<EOL
[Unit]
Description=Firewall Manager
After=network.target

[Service]
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin"
EnvironmentFile=$CONFIG_DIR/.env
ExecStart=$VENV_DIR/bin/uvicorn app:app --host 0.0.0.0 --port 8000 --proxy-headers
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=$SERVICE_NAME

# Configuration de sécurité
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOL

# Activation du service
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

# Initialisation de la base de données
echo -e "\n${BLUE}Initialisation de la base de données...${NC}"
sudo -u $APP_USER $VENV_DIR/bin/python $APP_DIR/app/scripts/init_db.py

# Vérification de la sécurité
echo -e "\n${BLUE}Vérification de la sécurité...${NC}"
$VENV_DIR/bin/python $APP_DIR/app/scripts/check_security.py

# Exécution du script de post-installation
$VENV_DIR/bin/python $APP_DIR/app/scripts/post_install.py

# Configuration de Nginx
echo -e "${BLUE}[8/8] Configuration de Nginx...${NC}"
cat > /etc/nginx/sites-available/$SERVICE_NAME <<EOL
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Augmentation de la taille maximale des requêtes
    client_max_body_size 20M;

    # Désactiver l'affichage de la version de Nginx
    server_tokens off;
}
EOL

# Activation de la configuration Nginx
ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test de la configuration Nginx
nginx -t || error_exit "Erreur dans la configuration Nginx"
systemctl restart nginx

# Configuration du pare-feu UFW
echo -e "${BLUE}Configuration du pare-feu...${NC}"
ufw allow 'Nginx Full'
ufw allow 'OpenSSH'
ufw --force enable

# Installation terminée
IP_ADDRESS=$(hostname -I | awk '{print $1}')

echo -e "\n${GREEN}=== Installation terminée avec succès ===${NC}"
echo -e "\n${YELLOW}Accès à l'interface :${NC} http://$IP_ADDRESS"
echo -e "${YELLOW}Documentation API :${NC} http://$IP_ADDRESS/docs"
echo -e "\n${YELLOW}Fichiers importants :${NC}"
echo "  - Répertoire de l'application : $APP_DIR"
echo "  - Fichiers de logs : $LOG_DIR"
echo "  - Fichier de configuration : $CONFIG_DIR/.env"
echo -e "\n${YELLOW}Commandes utiles :${NC}"
echo "  - Démarrer le service : systemctl start $SERVICE_NAME"
echo "  - Arrêter le service : systemctl stop $SERVICE_NAME"
echo "  - Voir les logs : journalctl -u $SERVICE_NAME -f"
echo -e "\n${GREEN}N'oubliez pas de configurer un certificat SSL avec Let's Encrypt !${NC}"
echo -e "Pour plus d'informations, consultez la documentation.\n"

exit 0
