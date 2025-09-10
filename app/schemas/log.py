"""
Schémas pour les journaux d'activité
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator, HttpUrl

class LogLevel(str, Enum):
    """Niveaux de gravité des logs"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogCategory(str, Enum):
    """Catégories de logs"""
    AUTH = "authentication"
    RULE = "firewall_rule"
    SYSTEM = "system"
    NETWORK = "network"
    SECURITY = "security"
    BACKUP = "backup"
    UPDATE = "update"
    OTHER = "other"

class LogBase(BaseModel):
    """Schéma de base pour les logs"""
    level: LogLevel = Field(LogLevel.INFO, description="Niveau de gravité du log")
    category: LogCategory = Field(LogCategory.OTHER, description="Catégorie du log")
    source: Optional[str] = Field(None, max_length=100, description="Source du log (module, composant, etc.)")
    message: str = Field(..., description="Message du log")
    details: Optional[Dict[str, Any]] = Field(None, description="Détails supplémentaires au format JSON")
    
    # Métadonnées de la requête
    ip_address: Optional[str] = Field(None, description="Adresse IP de l'utilisateur")
    user_agent: Optional[str] = Field(None, description="User-Agent de la requête")
    
    # Pour le suivi des actions
    action: Optional[str] = Field(None, max_length=100, description="Action effectuée (CRUD, etc.)")
    object_type: Optional[str] = Field(None, max_length=100, description="Type d'objet concerné")
    object_id: Optional[Union[int, str]] = Field(None, description="ID de l'objet concerné")
    
    class Config:
        schema_extra = {
            "example": {
                "level": "info",
                "category": "firewall_rule",
                "source": "firewall.api",
                "message": "Nouvelle règle de pare-feu créée",
                "details": {"rule_id": 42, "name": "Allow HTTP"},
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "action": "create",
                "object_type": "firewall_rule",
                "object_id": 42
            }
        }

class LogCreate(LogBase):
    """Schéma pour la création d'un log"""
    pass

class LogUpdate(BaseModel):
    """Schéma pour la mise à jour d'un log"""
    level: Optional[LogLevel] = None
    category: Optional[LogCategory] = None
    source: Optional[str] = None
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    class Config:
        schema_extra = {
            "example": {
                "level": "warning",
                "details": {"additional_info": "Plus d'informations"}
            }
        }

class LogInDBBase(LogBase):
    """Schéma de base pour un log en base de données"""
    id: int
    timestamp: datetime = Field(..., description="Date et heure de l'événement")
    user_id: Optional[int] = Field(None, description="ID de l'utilisateur associé")
    created_at: datetime = Field(..., description="Date de création de l'entrée")
    updated_at: Optional[datetime] = Field(None, description="Date de dernière mise à jour")
    
    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "timestamp": "2023-01-01T12:00:00",
                "level": "info",
                "category": "firewall_rule",
                "source": "firewall.api",
                "message": "Nouvelle règle de pare-feu créée",
                "details": {"rule_id": 42, "name": "Allow HTTP"},
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "action": "create",
                "object_type": "firewall_rule",
                "object_id": 42,
                "user_id": 1,
                "created_at": "2023-01-01T12:00:00",
                "updated_at": "2023-01-01T12:00:00"
            }
        }

class Log(LogInDBBase):
    """Schéma pour la lecture d'un log"""
    pass

class LogInDB(LogInDBBase):
    """Schéma pour un log en base de données avec relations"""
    user: Optional[Dict[str, Any]] = Field(None, description="Informations sur l'utilisateur associé")
    
    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "timestamp": "2023-01-01T12:00:00",
                "level": "info",
                "category": "firewall_rule",
                "source": "firewall.api",
                "message": "Nouvelle règle de pare-feu créée",
                "details": {"rule_id": 42, "name": "Allow HTTP"},
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "action": "create",
                "object_type": "firewall_rule",
                "object_id": 42,
                "user_id": 1,
                "user": {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@example.com"
                },
                "created_at": "2023-01-01T12:00:00",
                "updated_at": "2023-01-01T12:00:00"
            }
        }

class LogFilter(BaseModel):
    """Filtres pour la recherche de logs"""
    start_date: Optional[datetime] = Field(
        None, 
        description="Date de début pour la recherche (inclusive)"
    )
    end_date: Optional[datetime] = Field(
        None, 
        description="Date de fin pour la recherche (inclusive)"
    )
    level: Optional[List[LogLevel]] = Field(
        None, 
        description="Filtrer par niveau de gravité"
    )
    category: Optional[List[LogCategory]] = Field(
        None, 
        description="Filtrer par catégorie"
    )
    source: Optional[str] = Field(
        None, 
        description="Filtrer par source (recherche insensible à la casse)"
    )
    message: Optional[str] = Field(
        None, 
        description="Rechercher dans le message (recherche insensible à la casse)"
    )
    ip_address: Optional[str] = Field(
        None, 
        description="Filtrer par adresse IP"
    )
    user_id: Optional[int] = Field(
        None, 
        description="Filtrer par ID d'utilisateur"
    )
    action: Optional[str] = Field(
        None, 
        description="Filtrer par action (ex: create, update, delete)"
    )
    object_type: Optional[str] = Field(
        None, 
        description="Filtrer par type d'objet (ex: user, rule, backup)"
    )
    object_id: Optional[Union[int, str]] = Field(
        None, 
        description="Filtrer par ID d'objet"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "start_date": "2023-01-01T00:00:00",
                "end_date": "2023-01-31T23:59:59",
                "level": ["error", "critical"],
                "category": ["security", "firewall_rule"],
                "source": "api",
                "message": "failed",
                "ip_address": "192.168.1.1",
                "user_id": 1,
                "action": "create",
                "object_type": "firewall_rule"
            }
        }

class LogResponse(BaseModel):
    """Réponse pour une liste de logs avec pagination"""
    items: List[LogInDB] = Field(..., description="Liste des logs")
    total: int = Field(..., description="Nombre total de logs correspondant aux critères")
    page: int = Field(..., description="Numéro de la page actuelle")
    size: int = Field(..., description="Nombre d'éléments par page")
    pages: int = Field(..., description="Nombre total de pages")
    
    class Config:
        schema_extra = {
            "example": {
                "items": [
                    {
                        "id": 1,
                        "timestamp": "2023-01-01T12:00:00",
                        "level": "error",
                        "category": "security",
                        "message": "Échec de la connexion",
                        "ip_address": "192.168.1.1",
                        "user": {
                            "id": 1,
                            "username": "admin"
                        },
                        "created_at": "2023-01-01T12:00:00"
                    }
                ],
                "total": 1,
                "page": 1,
                "size": 10,
                "pages": 1
            }
        }
