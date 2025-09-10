#!/bin/bash

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction pour afficher un message d'erreur et quitter
function error_exit {
    echo -e "${RED}Erreur: $1${NC}" >&2
    exit 1
}

# Vérification des droits root
if [ "$EUID" -ne 0 ]; then 
    error_exit "Ce script doit être exécuté en tant que root. Utilisez 'sudo'."
fi

# Message de bienvenue
echo -e "\n${GREEN}=== Installation de Firewall Manager ===${NC}"
echo -e "${YELLOW}Ce script va installer Firewall Manager sur votre système.${NC}"
echo -e "${YELLOW}Cela peut prendre quelques minutes...${NC}"

# Mise à jour du système
echo -e "\n${YELLOW}[1/6] Mise à jour du système...${NC}"
apt-get update && apt-get upgrade -y

# Installation des dépendances
echo -e "\n${YELLOW}[2/6] Installation des dépendances...${NC}"
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    ufw \
    nginx \
    git \
    curl

# Création de l'utilisateur et des répertoires
echo -e "\n${YELLOW}[3/6] Configuration du système...${NC}"
if ! id -u firewall >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin firewall || error_exit "Échec de la création de l'utilisateur firewall"
fi

# Création des répertoires
mkdir -p /opt/firewall-manager
chown -R firewall:firewall /opt/firewall-manager

# Téléchargement de l'application
echo -e "\n${YELLOW}[4/6] Téléchargement de l'application...${NC}"
cd /opt/firewall-manager
sudo -u firewall git clone https://github.com/votre-utilisateur/firewall-manager.git . || error_exit "Échec du clonage du dépôt"

# Configuration de l'environnement
echo -e "\n${YELLOW}[5/6] Configuration de l'application...${NC}"
sudo -u firewall python3 -m venv venv || error_exit "Échec de la création de l'environnement virtuel"
sudo -u firewall venv/bin/pip install --upgrade pip
sudo -u firewall venv/bin/pip install -r requirements.txt || error_exit "Échec de l'installation des dépendances Python"

# Configuration du service systemd
cat > /etc/systemd/system/firewall-manager.service <<EOL
[Unit]
Description=Firewall Manager
After=network.target

[Service]
User=firewall
Group=firewall
WorkingDirectory=/opt/firewall-manager
Environment="PATH=/opt/firewall-manager/venv/bin"
ExecStart=/opt/firewall-manager/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000 --proxy-headers
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

# Activation du service
systemctl daemon-reload
systemctl enable firewall-manager
systemctl start firewall-manager

# Configuration de Nginx
cat > /etc/nginx/sites-available/firewall-manager <<EOL
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
}
EOL

ln -sf /etc/nginx/sites-available/firewall-manager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# Configuration du pare-feu
echo -e "\n${YELLOW}[6/6] Configuration du pare-feu...${NC}"
ufw allow 'Nginx Full'
ufw allow 'OpenSSH'
echo "y" | ufw --force enable

# Initialisation de la base de données
echo -e "\n${YELLOW}Initialisation de la base de données...${NC}"
sudo -u firewall /opt/firewall-manager/venv/bin/python /opt/firewall-manager/app/scripts/init_db.py

# Récupération de l'adresse IP
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Message de fin
echo -e "\n${GREEN}=== Installation terminée avec succès ! ===${NC}"
echo -e "\n${YELLOW}Accès à l'interface :${NC} http://$IP_ADDRESS"
echo -e "${YELLOW}Documentation API :${NC} http://$IP_ADDRESS/docs"

# Demander si l'utilisateur souhaite configurer les clés API maintenant
read -p "Voulez-vous configurer les clés API pour les services d'IA maintenant ? (O/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[OoYy]$ ]]; then
    echo -e "\n${YELLOW}Configuration des clés API...${NC}"
    sudo -u firewall /opt/firewall-manager/venv/bin/python /opt/firewall-manager/app/scripts/configure_ai.py
    
    # Redémarrer le service pour appliquer les changements
    systemctl restart firewall-manager
    echo -e "\n✅ Configuration des services d'IA terminée !"
fi

# Afficher les commandes utiles
echo -e "\n${YELLOW}Commandes utiles :${NC}"
echo -e "\n${YELLOW}Créer un utilisateur administrateur :${NC}"
echo "  sudo /opt/firewall-manager/venv/bin/python /opt/firewall-manager/app/scripts/create_user.py"

echo -e "\n${YELLOW}Configurer les services d'IA :${NC}"
echo "  sudo /opt/firewall-manager/venv/bin/python /opt/firewall-manager/app/scripts/configure_ai.py"

echo -e "\n${YELLOW}Gérer le service :${NC}"
echo "  sudo systemctl start|stop|restart|status firewall-manager"

echo -e "\n${YELLOW}Voir les logs :${NC}"
echo "  sudo journalctl -u firewall-manager -f"

echo -e "\n${YELLOW}Pour accéder à l'interface :${NC}"
echo "  http://$IP_ADDRESS"

exit 0
