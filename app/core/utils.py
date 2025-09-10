"""
Utilitaires généraux
"""
import subprocess
import shlex
import ipaddress
import re
from typing import Optional, Dict, Any, List, Union, Tuple
import socket
import platform
import psutil
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def run_command(
    command: str,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = 60,
    shell: bool = False,
    check: bool = True
) -> Tuple[int, str, str]:
    """
    Exécute une commande système de manière sécurisée
    
    Args:
        command: Commande à exécuter
        cwd: Répertoire de travail
        env: Variables d'environnement
        timeout: Délai d'attente en secondes
        shell: Utiliser le shell pour l'exécution
        check: Lancer une exception en cas d'erreur
        
    Returns:
        Tuple (code_retour, sortie_standard, sortie_erreur)
    """
    try:
        if not shell and isinstance(command, str):
            command = shlex.split(command)
            
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
            shell=shell,
            text=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise RuntimeError(f"La commande a expiré après {timeout} secondes")
            
        if check and process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode, command, stdout, stderr
            )
            
        return process.returncode, stdout, stderr
        
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de la commande: {e}")
        if check:
            raise
        return -1, "", str(e)

def is_valid_ip(ip: str) -> bool:
    """Vérifie si une chaîne est une adresse IP valide"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port: Union[int, str]) -> bool:
    """Vérifie si un numéro de port est valide"""
    try:
        port = int(port)
        return 0 <= port <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_cidr(cidr: str) -> bool:
    """Vérifie si une chaîne est un CIDR valide"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def get_system_info() -> Dict[str, Any]:
    """Récupère des informations sur le système"""
    try:
        # Informations de base
        info = {
            "system": {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            },
            "cpu": {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "usage_percent": psutil.cpu_percent(interval=1, percpu=True),
                "total_usage_percent": psutil.cpu_percent(interval=1),
            },
            "memory": {"total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "used": psutil.virtual_memory().used,
                "percent": psutil.virtual_memory().percent,
                "free": psutil.virtual_memory().free,
            },
            "disk": {
                "total": psutil.disk_usage("/").total,
                "used": psutil.disk_usage("/").used,
                "free": psutil.disk_usage("/").free,
                "percent": psutil.disk_usage("/").percent,
            },
            "boot_time": datetime.fromtimestamp(psutil.boot_time()),
            "uptime": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
        }
        
        # Informations réseau
        net_io = psutil.net_io_counters()
        info["network"] = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "error_in": net_io.errin,
            "error_out": net_io.errout,
            "drop_in": net_io.dropin,
            "drop_out": net_io.dropout,
        }
        
        # Interfaces réseau
        info["network"]["interfaces"] = []
        for name, addrs in psutil.net_if_addrs().items():
            iface = {"name": name, "addresses": []}
            for addr in addrs:
                iface["addresses"].append({
                    "family": addr.family.name,
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast,
                    "ptp": addr.ptp,
                })
            info["network"]["interfaces"].append(iface)
        
        return info
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des informations système: {e}")
        raise

def format_bytes(size: int, binary: bool = False) -> str:
    """Formate une taille en octets en une chaîne lisible"""
    base = 1024 if binary else 1000
    prefixes = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
    prefix = ''
    
    for prefix in prefixes:
        if abs(size) < base:
            return f"{size:.2f} {prefix}B"
        size /= base
    
    return f"{size:.2f} {prefix}B"

def parse_port_range(port_range: str) -> List[int]:
    """
    Parse une plage de ports (ex: "80", "80-85", "80,443,8080-8090")
    
    Returns:
        Liste des ports uniques triés
    """
    ports = set()
    
    for part in port_range.split(','):
        part = part.strip()
        if not part:
            continue
            
        if '-' in part:
            # Plage de ports (ex: 80-85)
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError("Les ports doivent être entre 1 et 65535")
                ports.update(range(min(start, end), max(start, end) + 1))
            except ValueError as e:
                raise ValueError(f"Plage de ports invalide: {part}") from e
        else:
            # Port unique
            try:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError("Les ports doivent être entre 1 et 65535")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Port invalide: {part}") from e
    
    return sorted(ports)

def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Vérifie si un port est ouvert sur un hôte donné"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        return False

def get_network_interfaces() -> List[Dict[str, Any]]:
    """Récupère la liste des interfaces réseau"""
    interfaces = []
    
    for name, addrs in psutil.net_if_addrs().items():
        iface = {
            "name": name,
            "addresses": [],
            "stats": psutil.net_if_stats().get(name, {})
        }
        
        for addr in addrs:
            if addr.family == socket.AF_INET:
                iface["addresses"].append({
                    "type": "IPv4",
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })
            elif addr.family == socket.AF_INET6:
                iface["addresses"].append({
                    "type": "IPv6",
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })
            else:
                iface["addresses"].append({
                    "type": "LINK",
                    "address": addr.address
                })
        
        interfaces.append(iface)
    
    return interfaces
