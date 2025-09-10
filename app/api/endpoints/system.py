"""
Endpoints pour les opérations système
"""
import subprocess
import platform
import psutil
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List

from app.core.security import get_current_active_user, get_current_superuser
from app.models.user import User

router = APIRouter()

@router.get("/status")
async def system_status(
    current_user: User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    """Récupère l'état du système"""
    try:
        # Informations système
        system_info = {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        }
        
        # Utilisation du CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Utilisation de la mémoire
        memory = psutil.virtual_memory()
        
        # Utilisation du disque
        disk = psutil.disk_usage('/')
        
        # Réseau
        net_io = psutil.net_io_counters()
        
        return {
            "system": system_info,
            "cpu": {
                "percent": cpu_percent,
                "count": cpu_count,
                "per_cpu": psutil.cpu_percent(interval=1, percpu=True)
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            },
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "error_in": net_io.errin,
                "error_out": net_io.errout,
                "drop_in": net_io.dropin,
                "drop_out": net_io.dropout
            },
            "uptime": psutil.boot_time()
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Erreur lors de la récupération des informations système: {str(e)}"
        )

@router.get("/services")
async def list_services(
    current_user: User = Depends(get_current_superuser)
) -> List[Dict[str, Any]]:
    """Liste les services système (nécessite les droits administrateur)"""
    try:
        if platform.system() == "Windows":
            raise HTTPException(
                status_code=501,
                detail="Cette fonctionnalité n'est pas disponible sur Windows"
            )
            
        # Commande pour lister les services sous Linux avec systemd
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la récupération des services: {result.stderr}"
            )
            
        services = []
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 4:
                service = {
                    "name": parts[0],
                    "loaded": parts[1] == "loaded",
                    "active": parts[2] == "active",
                    "sub": parts[3],
                    "description": " ".join(parts[4:]) if len(parts) > 4 else ""
                }
                services.append(service)
                
        return services
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Erreur lors de la récupération des services: {str(e)}"
        )

@router.post("/service/{service_name}/{action}")
asdef control_service(
    service_name: str,
    action: str,
    current_user: User = Depends(get_current_superuser)
) -> Dict[str, str]:
    """Contrôle un service système (démarrer, arrêter, redémarrer, etc.)"""
    valid_actions = ["start", "stop", "restart", "reload", "enable", "disable"]
    
    if action not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Action non valide. Actions autorisées: {', '.join(valid_actions)}"
        )
    
    try:
        if platform.system() == "Windows":
            raise HTTPException(
                status_code=501,
                detail="Cette fonctionnalité n'est pas disponible sur Windows"
            )
            
        result = subprocess.run(
            ["systemctl", action, service_name],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de l'exécution de la commande: {result.stderr}"
            )
            
        return {"status": "success", "message": f"Service {service_name} {action} avec succès"}
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Erreur lors du contrôle du service: {str(e)}"
        )
