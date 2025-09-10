"""
Schémas pour les paramètres de l'application
"""
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from pydantic import BaseModel, Field, validator, HttpUrl, EmailStr

class SettingType(str, Enum):
    """Types de paramètres"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    JSON = "json"
    PASSWORD = "password"
    EMAIL = "email"
    URL = "url"
    SELECT = "select"
    MULTISELECT = "multiselect"

class SettingBase(BaseModel):
    """Schéma de base pour les paramètres"""
    key: str = Field(..., max_length=100, description="Clé unique du paramètre")
    value: Optional[Any] = Field(None, description="Valeur du paramètre")
    value_type: SettingType = Field(..., description="Type de la valeur")
    is_public: bool = Field(True, description="Si le paramètre est public")
    is_required: bool = Field(False, description="Si le paramètre est requis")
    category: str = Field("general", description="Catégorie du paramètre")
    description: Optional[str] = Field(None, description="Description du paramètre")
    options: Optional[List[Dict[str, Any]]] = Field(
        None, 
        description="Options pour les types select/multiselect"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "key": "app_name",
                "value": "Firewall Manager",
                "value_type": "string",
                "is_public": True,
                "is_required": True,
                "category": "general",
                "description": "Nom de l'application",
                "options": None
            }
        }

class SettingCreate(SettingBase):
    """Schéma pour la création d'un paramètre"""
    pass

class SettingUpdate(BaseModel):
    """Schéma pour la mise à jour d'un paramètre"""
    value: Optional[Any] = Field(None, description="Nouvelle valeur du paramètre")
    is_public: Optional[bool] = Field(None, description="Si le paramètre est public")
    is_required: Optional[bool] = Field(None, description="Si le paramètre est requis")
    category: Optional[str] = Field(None, description="Nouvelle catégorie")
    description: Optional[str] = Field(None, description="Nouvelle description")
    options: Optional[List[Dict[str, Any]]] = Field(
        None, 
        description="Nouvelles options pour les types select/multiselect"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "value": "Mon Firewall",
                "description": "Nom personnalisé de l'application",
                "is_public": True
            }
        }

class SettingInDBBase(SettingBase):
    """Schéma de base pour un paramètre en base de données"""
    id: int
    created_at: datetime = Field(..., description="Date de création")
    updated_at: Optional[datetime] = Field(None, description="Date de dernière mise à jour")
    
    class Config:
        orm_mode = True

class Setting(SettingInDBBase):
    """Schéma pour la lecture d'un paramètre"""
    pass

class SettingInDB(SettingInDBBase):
    """Schéma pour un paramètre en base de données avec relations"""
    created_by: Optional[Dict[str, Any]] = Field(None, description="Utilisateur ayant créé le paramètre")
    updated_by: Optional[Dict[str, Any]] = Field(None, description="Dernier utilisateur ayant modifié le paramètre")
    
    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "key": "app_name",
                "value": "Mon Firewall",
                "value_type": "string",
                "is_public": True,
                "is_required": True,
                "category": "general",
                "description": "Nom de l'application",
                "options": None,
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-02T12:00:00",
                "created_by": {"username": "admin"},
                "updated_by": {"username": "user1"}
            }
        }

class SettingFilter(BaseModel):
    """Filtres pour la recherche de paramètres"""
    key: Optional[str] = Field(None, description="Recherche par clé (insensible à la casse)")
    category: Optional[str] = Field(None, description="Filtrer par catégorie")
    is_public: Optional[bool] = Field(None, description="Filtrer par visibilité")
    is_required: Optional[bool] = Field(None, description="Filtrer par statut requis")
    value_type: Optional[SettingType] = Field(None, description="Filtrer par type de valeur")
    
    class Config:
        schema_extra = {
            "example": {
                "category": "email",
                "is_public": False,
                "value_type": "string"
            }
        }

class SettingBulkUpdate(BaseModel):
    """Schéma pour la mise à jour en masse des paramètres"""
    settings: Dict[str, Any] = Field(
        ..., 
        description="Dictionnaire des paramètres à mettre à jour (clé: valeur)"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "settings": {
                    "app_name": "Mon Firewall",
                    "admin_email": "admin@example.com",
                    "items_per_page": 25
                }
            }
        }

class SettingExport(BaseModel):
    """Schéma pour l'export des paramètres"""
    include_private: bool = Field(
        False, 
        description="Inclure les paramètres privés (non publics)"
    )
    format: str = Field(
        "json", 
        description="Format d'export (json, yaml, env)",
        regex="^(json|yaml|env)$"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "include_private": True,
                "format": "json"
            }
        }

class SettingImport(BaseModel):
    """Schéma pour l'import des paramètres"""
    file: bytes = Field(..., description="Fichier contenant les paramètres à importer")
    format: str = Field(
        "json", 
        description="Format du fichier (json, yaml, env)",
        regex="^(json|yaml|env)$"
    )
    overwrite: bool = Field(
        False, 
        description="Écraser les paramètres existants"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "format": "json",
                "overwrite": False
            }
        }
