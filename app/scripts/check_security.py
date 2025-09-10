#!/usr/bin/env python3
"""
Vérification de la sécurité
Vérifie les configurations de sécurité critiques
"""
import os
import sys
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityChecker:
    """Classe pour vérifier les configurations de sécurité"""
    
    def __init__(self):
        self.checks_passed = 0
        self.checks_failed = 0
        self.checks_warning = 0
        self.results: List[Dict] = []
    
    def add_result(self, check_name: str, status: str, message: str) -> None:
        """Ajoute un résultat de vérification"""
        result = {
            'check': check_name,
            'status': status,
            'message': message
        }
        self.results.append(result)
        
        if status == 'PASS':
            self.checks_passed += 1
        elif status == 'WARNING':
            self.checks_warning += 1
        else:
            self.checks_failed += 1
    
    def check_file_permissions(self) -> None:
        """Vérifie les permissions des fichiers sensibles"""
        sensitive_files = [
            ('/etc/firewall-manager/.env', 0o640),
            ('/opt/firewall-manager/firewall.db', 0o600),
            ('/var/log/firewall-manager', 0o750)
        ]
        
        for file_path, expected_mode in sensitive_files:
            try:
                if not os.path.exists(file_path):
                    self.add_result(
                        f'File Permissions: {file_path}',
                        'WARNING',
                        f'Le fichier {file_path} n\'existe pas'
                    )
                    continue
                
                mode = os.stat(file_path).st_mode & 0o777
                if mode != expected_mode:
                    self.add_result(
                        f'File Permissions: {file_path}',
                        'FAIL',
                        f'Permissions incorrectes: {oct(mode)} (attendu: {oct(expected_mode)})'
                    )
                else:
                    self.add_result(
                        f'File Permissions: {file_path}',
                        'PASS',
                        f'Permissions correctes: {oct(mode)}'
                    )
            except Exception as e:
                self.add_result(
                    f'File Permissions: {file_path}',
                    'ERROR',
                    f'Erreur lors de la vérification: {str(e)}'
                )
    
    def check_firewall_rules(self) -> None:
        """Vérifie les règles de pare-feu de base"""
        try:
            # Vérifier si UFW est actif
            result = subprocess.run(
                ['ufw', 'status'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if 'active (exited)' in result.stdout:
                self.add_result(
                    'Firewall Status',
                    'PASS',
                    'Le pare-feu UFW est actif'
                )
                
                # Vérifier les règles de base
                required_ports = ['22/tcp', '80/tcp', '443/tcp']
                for port in required_ports:
                    if f"{port} " in result.stdout:
                        self.add_result(
                            f'Firewall Rule: {port}',
                            'PASS',
                            f'La règle pour le port {port} est configurée'
                        )
                    else:
                        self.add_result(
                            f'Firewall Rule: {port}',
                            'WARNING',
                            f'La règle pour le port {port} n\'est pas configurée'
                        )
            else:
                self.add_result(
                    'Firewall Status',
                    'FAIL',
                    'Le pare-feu UFW n\'est pas actif'
                )
                
        except FileNotFoundError:
            self.add_result(
                'Firewall Check',
                'FAIL',
                'UFW n\'est pas installé'
            )
        except Exception as e:
            self.add_result(
                'Firewall Check',
                'ERROR',
                f'Erreur lors de la vérification du pare-feu: {str(e)}'
            )
    
    def check_ssl_config(self) -> None:
        """Vérifie la configuration SSL"""
        nginx_conf = '/etc/nginx/sites-available/firewall-manager'
        
        try:
            if not os.path.exists(nginx_conf):
                self.add_result(
                    'SSL Configuration',
                    'WARNING',
                    'La configuration Nginx n\'a pas été trouvée'
                )
                return
                
            with open(nginx_conf, 'r') as f:
                config = f.read()
                
            if 'ssl_certificate' in config and 'ssl_certificate_key' in config:
                self.add_result(
                    'SSL Configuration',
                    'PASS',
                    'Le certificat SSL est configuré'
                )
                
                # Vérifier la version de TLS
                if 'ssl_protocols' in config and 'TLSv1.2' in config:
                    self.add_result(
                        'TLS Version',
                        'PASS',
                        'TLS 1.2+ est activé'
                    )
                else:
                    self.add_result(
                        'TLS Version',
                        'WARNING',
                        'Les versions de TLS ne sont pas correctement configurées'
                    )
            else:
                self.add_result(
                    'SSL Configuration',
                    'WARNING',
                    'Aucun certificat SSL configuré (recommandé pour la production)'
                )
                
        except Exception as e:
            self.add_result(
                'SSL Check',
                'ERROR',
                f'Erreur lors de la vérification SSL: {str(e)}'
            )
    
    def check_service_status(self) -> None:
        """Vérifie l'état du service"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'firewall-manager.service'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.add_result(
                    'Service Status',
                    'PASS',
                    'Le service firewall-manager est en cours d\'exécution'
                )
            else:
                self.add_result(
                    'Service Status',
                    'FAIL',
                    'Le service firewall-manager n\'est pas en cours d\'exécution'
                )
                
            # Vérifier si le service est activé au démarrage
            result = subprocess.run(
                ['systemctl', 'is-enabled', 'firewall-manager.service'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if 'enabled' in result.stdout:
                self.add_result(
                    'Service Auto-Start',
                    'PASS',
                    'Le service est configuré pour démarrer automatiquement'
                )
            else:
                self.add_result(
                    'Service Auto-Start',
                    'WARNING',
                    'Le service n\'est pas configuré pour démarrer automatiquement'
                )
                
        except Exception as e:
            self.add_result(
                'Service Check',
                'ERROR',
                f'Erreur lors de la vérification du service: {str(e)}'
            )
    
    def run_checks(self) -> None:
        """Exécute toutes les vérifications"""
        print("\n🔍 Exécution des vérifications de sécurité...\n")
        
        self.check_file_permissions()
        self.check_firewall_rules()
        self.check_ssl_config()
        self.check_service_status()
        
        # Affichage des résultats
        print("\n📊 Résultats des vérifications de sécurité:\n")
        
        for result in self.results:
            status = result['status']
            if status == 'PASS':
                status_display = f'\033[92m{status:8}\033[0m'
            elif status == 'WARNING':
                status_display = f'\033[93m{status:8}\033[0m'
            else:
                status_display = f'\033[91m{status:8}\033[0m'
            
            print(f"{status_display} {result['check']}: {result['message']}")
        
        # Résumé
        print("\n📋 Résumé:")
        print(f"  ✅ {self.checks_passed} vérifications réussies")
        print(f"  ⚠️  {self.checks_warning} avertissements")
        print(f"  ❌ {self.checks_failed} échecs")
        
        if self.checks_failed > 0:
            print("\n\033[91m✗ Des problèmes de sécurité critiques ont été détectés. Veuillez les corriger.\033[0m")
            sys.exit(1)
        elif self.checks_warning > 0:
            print("\n\033[93mℹ️  Des avertissements ont été détectés. Il est recommandé de les examiner.\033[0m")
            sys.exit(0)
        else:
            print("\n\033[92m✓ Toutes les vérifications de sécurité sont passées avec succès !\033[0m")
            sys.exit(0)

if __name__ == "__main__":
    print("\n🛡️  \033[1mVérification de la sécurité du Firewall Manager\033[0m 🛡️")
    print("=" * 60)
    
    checker = SecurityChecker()
    checker.run_checks()
