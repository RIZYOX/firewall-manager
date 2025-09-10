#!/bin/bash

# Configuration
APP_DIR="/opt/firewall-manager"
SERVICE_NAME="firewall-manager"
VENV_DIR="$APP_DIR/venv"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Vérification des privilèges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Erreur: Ce script doit être exécuté en tant que root.${NC}"
    echo "Utilisez : sudo $0"
    exit 1
fi

# Mise à jour et installation des dépendances
echo -e "${GREEN}[1/4] Mise à jour du système...${NC}"
apt update && apt upgrade -y

echo -e "${GREEN}[2/4] Installation des dépendances...${NC}"
apt install -y python3 python3-pip python3-venv ufw nginx

# Téléchargement et installation
echo -e "${GREEN}[3/4] Installation de l'application...${NC}"
mkdir -p $APP_DIR
cd $APP_DIR
wget -q https://github.com/RIZYOX/firewall-manager/archive/refs/heads/main.zip
unzip -q main.zip
mv firewall-manager-main/* .
rm -rf firewall-manager-main main.zip

# Configuration de l'environnement
python3 -m venv $VENV_DIR
source $VENV_DIR/bin/activate
pip install -q -r requirements.txt

# Configuration du service
echo -e "${GREEN}[4/4] Configuration du service...${NC}"
cat > /etc/systemd/system/$SERVICE_NAME.service <<EOL
[Unit]
Description=Firewall Manager
After=network.target

[Service]
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$VENV_DIR/bin/uvicorn app:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Configuration Nginx
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
    }
}
EOL

# Activation des services
systemctl daemon-reload
systemctl enable --now $SERVICE_NAME
ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# Configuration UFW
ufw allow 80/tcp
ufw allow 22/tcp
ufw --force enable

# Fin
IP=$(hostname -I | awk '{print $1}')
echo -e "\n${GREEN}✅ Installation terminée !${NC}"
echo -e "Accédez à l'interface : http://$IP"
echo -e "\nCommandes utiles :"
echo "  systemctl status $SERVICE_NAME"
echo "  journalctl -u $SERVICE_NAME -f"