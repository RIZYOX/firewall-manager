"""
Schémas de base utilisés dans toute l'application
"""
from typing import Any, Dict, Generic, List, Optional, TypeVar, Union
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl, validator
from datetime import datetime, date

# Type générique pour les réponses paginées
T = TypeVar('T')

class Status(str, Enum):
    """Statuts possibles d'une opération"""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class Message(BaseModel):
    """Schéma pour les messages de l'API"""
    detail: str = Field(..., description="Message détaillé")
    
    class Config:
        schema_extra = {
            "example": {"detail": "Opération effectuée avec succès"}
        }

class HealthCheck(BaseModel):
    """Schéma pour la vérification de l'état de l'API"""
    name: str = Field(..., description="Nom du service")
    version: str = Field(..., description="Version du service")
    status: str = Field(..., description="État du service")
    timestamp: datetime = Field(..., description="Horodatage de la vérification")
    
    @classmethod
    def healthy(cls, name: str, version: str):
        """Crée une réponse de bonne santé"""
        return cls(
            name=name,
            version=version,
            status="healthy",
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def unhealthy(cls, name: str, version: str, error: str):
        """Crée une réponse de mauvaise santé"""
        return cls(
            name=name,
            version=version,
            status=f"unhealthy: {error}",
            timestamp=datetime.utcnow()
        )

class HTTPError(BaseModel):
    """Schéma pour les erreurs HTTP standardisées"""
    code: int = Field(..., description="Code d'erreur HTTP")
    message: str = Field(..., description="Message d'erreur")
    details: Optional[Dict[str, Any]] = Field(None, description="Détails supplémentaires")
    
    class Config:
        schema_extra = {
            "example": {
                "code": 404,
                "message": "Ressource non trouvée",
                "details": {"resource": "user", "id": 42}
            }
        }

class ValidationError(BaseModel):
    """Schéma pour les erreurs de validation"""
    loc: List[str] = Field(..., description="Chemin du champ en erreur")
    msg: str = Field(..., description="Message d'erreur")
    type: str = Field(..., description="Type d'erreur")
    
    class Config:
        schema_extra = {
            "example": {
                "loc": ["body", "email"],
                "msg": "value is not a valid email address",
                "type": "value_error.email"
            }
        }

class ErrorResponse(BaseModel):
    """Réponse d'erreur standardisée"""
    status: Status = Status.ERROR
    error: HTTPError = Field(..., description="Détails de l'erreur")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "error",
                "error": {
                    "code": 404,
                    "message": "Utilisateur non trouvé",
                    "details": {"user_id": 42}
                }
            }
        }

class SuccessResponse(BaseModel, Generic[T]):
    """Réponse de succès standardisée avec données typées"""
    status: Status = Status.SUCCESS
    data: T = Field(..., description="Données de la réponse")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "success",
                "data": {"id": 1, "name": "Exemple"}
            }
        }

class PaginationParams(BaseModel):
    """Paramètres de pagination"""
    page: int = Field(1, ge=1, description="Numéro de la page (commence à 1)")
    size: int = Field(10, ge=1, le=100, description="Nombre d'éléments par page")
    
    @validator('page')
    def page_must_be_positive(cls, v):
        if v < 1:
            raise ValueError("Le numéro de page doit être supérieur à 0")
        return v
    
    class Config:
        schema_extra = {
            "example": {"page": 1, "size": 10}
        }

class OrderingParams(BaseModel):
    """Paramètres de tri"""
    order_by: str = Field("id", description="Champ de tri")
    order: str = Field("asc", regex="^(asc|desc)$", description="Ordre de tri (asc/desc)")
    
    class Config:
        schema_extra = {
            "example": {"order_by": "created_at", "order": "desc"}
        }

class FilterParams(BaseModel):
    """Paramètres de filtrage génériques"""
    filters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Filtres à appliquer (clé=valeur)"
    )
    
    class Config:
        schema_extra = {
            "example": {"filters": {"is_active": True, "role": "admin"}}
        }

class ResponseSchema(BaseModel):
    """Schéma de base pour les réponses API (compatibilité ascendante)"""
    success: bool = Field(..., description="Indique si la requête a réussi")
    message: Optional[str] = Field(None, description="Message détaillé")
    data: Optional[Any] = Field(None, description="Données de la réponse")
    
    @classmethod
    def success_response(
        cls, 
        data: Any = None, 
        message: str = "Opération réussie"
    ) -> Dict[str, Any]:
        """Crée une réponse de succès"""
        return {
            "success": True,
            "message": message,
            "data": data
        }
    
    @classmethod
    def error_response(
        cls, 
        message: str = "Une erreur est survenue", 
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Crée une réponse d'erreur"""
        return {
            "success": False,
            "message": message,
            "error": {
                "code": status_code,
                "details": details or {}
            }
        }

class PaginatedResponse(BaseModel, Generic[T]):
    """Schéma pour les réponses paginées"""
    items: List[T] = Field(..., description="Liste des éléments")
    total: int = Field(..., description="Nombre total d'éléments")
    page: int = Field(..., description="Numéro de la page actuelle")
    size: int = Field(..., description="Taille de la page")
    pages: int = Field(..., description="Nombre total de pages")
    
    @classmethod
    def from_list(
        cls, 
        items: List[T], 
        total: int, 
        page: int, 
        size: int
    ) -> 'PaginatedResponse[T]':
        """Crée une réponse paginée à partir d'une liste"""
        return cls(
            items=items,
            total=total,
            page=page,
            size=size,
            pages=(total + size - 1) // size if size > 0 else 1
        )

class Token(BaseModel):
    """Schéma pour les tokens JWT"""
    access_token: str = Field(..., description="Token d'accès")
    token_type: str = Field("bearer", description="Type de token")
    expires_in: Optional[int] = Field(None, description="Durée de validité en secondes")

class TokenData(BaseModel):
    """Données encodées dans le token JWT"""
    username: Optional[str] = None
    scopes: List[str] = []

class UserBase(BaseModel):
    """Schéma de base pour un utilisateur"""
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_-]+$")
    email: str = Field(..., regex=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    is_active: bool = True
    is_superuser: bool = False

class UserCreate(UserBase):
    """Schéma pour la création d'un utilisateur"""
    password: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    """Schéma pour la mise à jour d'un utilisateur"""
    email: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8)

class UserInDBBase(UserBase):
    """Schéma de base pour un utilisateur en base de données"""
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

class User(UserInDBBase):
    """Schéma pour la lecture d'un utilisateur (sans mot de passe)"""
    pass

class UserInDB(UserInDBBase):
    """Schéma pour un utilisateur en base de données (avec mot de passe hashé)"""
    hashed_password: str

class Message(BaseModel):
    """Schéma pour les messages de l'API"""
    detail: str = Field(..., description="Message détaillé")

class HealthCheck(BaseModel):
    """Schéma pour la vérification de l'état de l'API"""
    name: str = Field(..., description="Nom du service")
    version: str = Field(..., description="Version du service")
    status: str = Field(..., description="État du service")
    timestamp: datetime = Field(..., description="Horodatage de la vérification")
    
    @classmethod
    def healthy(cls, name: str, version: str) -> 'HealthCheck':
        """Crée une réponse de bonne santé"""
        return cls(
            name=name,
            version=version,
            status="healthy",
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def unhealthy(cls, name: str, version: str, error: str) -> 'HealthCheck':
        """Crée une réponse de mauvaise santé"""
        return cls(
            name=name,
            version=version,
            status=f"unhealthy: {error}",
            timestamp=datetime.utcnow()
        )
