"""
Schémas pour les sauvegardes
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator, HttpUrl

class BackupStatus(str, Enum):
    """Statuts possibles d'une sauvegarde"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RESTORING = "restoring"
    RESTORED = "restored"

class BackupType(str, Enum):
    """Types de sauvegarde"""
    FULL = "full"
    DATABASE = "database"
    CONFIG = "config"
    RULES = "rules"

class BackupBase(BaseModel):
    """Schéma de base pour les sauvegardes"""
    name: str = Field(..., max_length=255, description="Nom de la sauvegarde")
    description: Optional[str] = Field(None, description="Description de la sauvegarde")
    backup_type: BackupType = Field(..., description="Type de sauvegarde")
    is_encrypted: bool = Field(False, description="Si la sauvegarde est chiffrée")
    metadata: Optional[Dict[str, Any]] = Field(
        None, 
        description="Métadonnées supplémentaires au format JSON"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "name": "sauvegarde-complete-2023",
                "description": "Sauvegarde complète du système",
                "backup_type": "full",
                "is_encrypted": True,
                "metadata": {
                    "version": "1.0.0",
                    "notes": "Sauvegarde avant mise à jour majeure"
                }
            }
        }

class BackupCreate(BackupBase):
    """Schéma pour la création d'une sauvegarde"""
    password: Optional[str] = Field(
        None, 
        min_length=8, 
        max_length=100,
        description="Mot de passe pour le chiffrement (si is_encrypted=True)"
    )
    
    @validator('password', pre=True, always=True)
    def validate_password(cls, v, values):
        """Valide que le mot de passe est fourni si le chiffrement est activé"""
        if values.get('is_encrypted') and not v:
            raise ValueError("Un mot de passe est requis pour les sauvegardes chiffrées")
        return v

class BackupUpdate(BaseModel):
    """Schéma pour la mise à jour d'une sauvegarde"""
    name: Optional[str] = Field(None, max_length=255, description="Nouveau nom de la sauvegarde")
    description: Optional[str] = Field(None, description="Nouvelle description")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Nouvelles métadonnées")
    
    class Config:
        schema_extra = {
            "example": {
                "name": "sauvegarde-complete-2023-v2",
                "description": "Sauvegarde complète du système (mise à jour)",
                "metadata": {
                    "version": "1.0.1",
                    "notes": "Sauvegarde après correction de bogue"
                }
            }
        }

class BackupInDBBase(BackupBase):
    """Schéma de base pour une sauvegarde en base de données"""
    id: int
    filename: str = Field(..., description="Nom du fichier de sauvegarde")
    filepath: str = Field(..., description="Chemin complet du fichier de sauvegarde")
    file_size: int = Field(0, description="Taille du fichier en octets")
    status: BackupStatus = Field(..., description="Statut actuel de la sauvegarde")
    user_id: Optional[int] = Field(None, description="ID de l'utilisateur ayant créé la sauvegarde")
    started_at: Optional[datetime] = Field(None, description="Date de début de la sauvegarde")
    completed_at: Optional[datetime] = Field(None, description="Date de fin de la sauvegarde")
    error_message: Optional[str] = Field(None, description="Message d'erreur en cas d'échec")
    created_at: datetime = Field(..., description="Date de création de l'entrée")
    updated_at: Optional[datetime] = Field(None, description="Date de dernière mise à jour")
    
    class Config:
        orm_mode = True

class Backup(BackupInDBBase):
    """Schéma pour la lecture d'une sauvegarde"""
    file_size_human: str = Field(..., description="Taille du fichier formatée (ex: 1.5 MB)")
    duration: Optional[float] = Field(None, description="Durée de la sauvegarde en secondes")
    
    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "name": "sauvegarde-complete-2023",
                "description": "Sauvegarde complète du système",
                "backup_type": "full",
                "is_encrypted": True,
                "metadata": {"version": "1.0.0"},
                "filename": "backup_20230101_120000.zip",
                "filepath": "/backups/backup_20230101_120000.zip",
                "file_size": 10485760,
                "file_size_human": "10.0 MB",
                "status": "completed",
                "user_id": 1,
                "started_at": "2023-01-01T12:00:00",
                "completed_at": "2023-01-01T12:05:30",
                "duration": 330.5,
                "created_at": "2023-01-01T12:00:00",
                "updated_at": "2023-01-01T12:05:30"
            }
        }

class BackupInDB(BackupInDBBase):
    """Schéma pour une sauvegarde en base de données avec relations"""
    user: Optional[Dict[str, Any]] = Field(None, description="Informations sur l'utilisateur")
    
    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "name": "sauvegarde-complete-2023",
                "description": "Sauvegarde complète du système",
                "backup_type": "full",
                "is_encrypted": True,
                "metadata": {"version": "1.0.0"},
                "filename": "backup_20230101_120000.zip",
                "filepath": "/backups/backup_20230101_120000.zip",
                "file_size": 10485760,
                "status": "completed",
                "user_id": 1,
                "user": {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@example.com"
                },
                "started_at": "2023-01-01T12:00:00",
                "completed_at": "2023-01-01T12:05:30",
                "created_at": "2023-01-01T12:00:00",
                "updated_at": "2023-01-01T12:05:30"
            }
        }

class BackupFilter(BaseModel):
    """Filtres pour la recherche de sauvegardes"""
    name: Optional[str] = Field(None, description="Recherche par nom (insensible à la casse)")
    backup_type: Optional[BackupType] = Field(None, description="Filtrer par type de sauvegarde")
    status: Optional[BackupStatus] = Field(None, description="Filtrer par statut")
    user_id: Optional[int] = Field(None, description="Filtrer par ID d'utilisateur")
    start_date: Optional[datetime] = Field(None, description="Date de début (création)")
    end_date: Optional[datetime] = Field(None, description="Date de fin (création)")
    is_encrypted: Optional[bool] = Field(None, description="Filtrer par statut de chiffrement")
    
    class Config:
        schema_extra = {
            "example": {
                "name": "sauvegarde",
                "backup_type": "full",
                "status": "completed",
                "user_id": 1,
                "start_date": "2023-01-01T00:00:00",
                "end_date": "2023-01-31T23:59:59",
                "is_encrypted": True
            }
        }

class BackupResponse(BaseModel):
    """Réponse pour une liste de sauvegardes avec pagination"""
    items: List[BackupInDB] = Field(..., description="Liste des sauvegardes")
    total: int = Field(..., description="Nombre total de sauvegardes correspondant aux critères")
    page: int = Field(..., description="Numéro de la page actuelle")
    size: int = Field(..., description="Nombre d'éléments par page")
    pages: int = Field(..., description="Nombre total de pages")
    
    class Config:
        schema_extra = {
            "example": {
                "items": [
                    {
                        "id": 1,
                        "name": "sauvegarde-complete-2023",
                        "backup_type": "full",
                        "file_size_human": "10.0 MB",
                        "status": "completed",
                        "created_at": "2023-01-01T12:00:00",
                        "user": {"username": "admin"}
                    }
                ],
                "total": 1,
                "page": 1,
                "size": 10,
                "pages": 1
            }
        }

class BackupRestore(BaseModel):
    """Schéma pour la restauration d'une sauvegarde"""
    backup_id: int = Field(..., description="ID de la sauvegarde à restaurer")
    password: Optional[str] = Field(
        None, 
        min_length=8, 
        max_length=100,
        description="Mot de passe pour le déchiffrement (si la sauvegarde est chiffrée)"
    )
    options: Optional[Dict[str, Any]] = Field(
        None,
        description="Options supplémentaires pour la restauration"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "backup_id": 1,
                "password": "motdepassesecurise",
                "options": {
                    "overwrite": True,
                    "skip_errors": False
                }
            }
        }

class BackupExport(BaseModel):
    """Schéma pour l'export d'une sauvegarde"""
    format: str = Field("zip", description="Format d'export (zip, tar.gz, etc.)")
    include_logs: bool = Field(True, description="Inclure les journaux dans l'export")
    include_config: bool = Field(True, description="Inclure la configuration dans l'export")
    
    class Config:
        schema_extra = {
            "example": {
                "format": "zip",
                "include_logs": True,
                "include_config": True
            }
        }
