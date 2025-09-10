"""
Schémas pour l'authentification et les tokens
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, EmailStr, Field, validator

class Token(BaseModel):
    """Schéma pour le token d'accès"""
    access_token: str = Field(..., description="Token d'accès JWT")
    token_type: str = Field(default="bearer", description="Type de token (toujours 'bearer')")
    expires_in: Optional[int] = Field(
        None, 
        description="Durée de validité du token en secondes"
    )
    refresh_token: Optional[str] = Field(
        None,
        description="Token de rafraîchissement pour obtenir un nouveau token d'accès"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 3600,
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }

class TokenPayload(BaseModel):
    """Payload du token JWT"""
    sub: Optional[int] = Field(None, description="ID de l'utilisateur")
    exp: Optional[datetime] = Field(None, description="Date d'expiration")
    iat: Optional[datetime] = Field(None, description="Date d'émission")
    jti: Optional[str] = Field(None, description="Identifiant unique du token")
    scopes: List[str] = Field(
        default_factory=list, 
        description="Liste des scopes (permissions) accordés"
    )
    
    class Config:
        extra = "ignore"  # Ignorer les champs supplémentaires

class TokenData(BaseModel):
    """Données du token pour l'authentification"""
    username: Optional[str] = Field(
        None, 
        description="Nom d'utilisateur (pour la rétrocompatibilité)"
    )
    email: Optional[EmailStr] = Field(
        None, 
        description="Email de l'utilisateur"
    )
    scopes: List[str] = Field(
        default_factory=list, 
        description="Liste des scopes (permissions) accordés"
    )
    
    @validator("scopes", pre=True)
    def validate_scopes(cls, v):
        """Valide que les scopes sont une liste"""
        if isinstance(v, str):
            return v.split()
        return v or []

class TokenCreate(BaseModel):
    """Schéma pour la création d'un token"""
    username: str = Field(..., description="Nom d'utilisateur")
    password: str = Field(..., description="Mot de passe")
    scopes: List[str] = Field(
        default_factory=list,
        description="Liste des scopes (permissions) demandés"
    )
    remember_me: bool = Field(
        False,
        description="Si vrai, le token aura une durée de vie plus longue"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "username": "johndoe",
                "password": "secret",
                "scopes": ["me", "rules:read"],
                "remember_me": False
            }
        }

class TokenRefresh(BaseModel):
    """Schéma pour le rafraîchissement d'un token"""
    refresh_token: str = Field(..., description="Token de rafraîchissement")
    
    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }

class TokenInDB(BaseModel):
    """Schéma pour un token en base de données"""
    id: int = Field(..., description="ID du token")
    user_id: int = Field(..., description="ID de l'utilisateur associé")
    jti: str = Field(..., description="Identifiant unique du token")
    token_type: str = Field(..., description="Type de token (access, refresh)")
    revoked: bool = Field(False, description="Si le token a été révoqué")
    expires: datetime = Field(..., description="Date d'expiration")
    created_at: datetime = Field(..., description="Date de création")
    updated_at: datetime = Field(..., description="Dernière mise à jour")
    
    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "user_id": 1,
                "jti": "2a4b6c8d0e1f3g5h7j9k0l1m2n3o4p5",
                "token_type": "access",
                "revoked": False,
                "expires": "2023-12-31T23:59:59",
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00"
            }
        }

class TokenRevoke(BaseModel):
    """Schéma pour la révocation d'un token"""
    jti: str = Field(..., description="Identifiant unique du token à révoquer")
    
    class Config:
        schema_extra = {
            "example": {
                "jti": "2a4b6c8d0e1f3g5h7j9k0l1m2n3o4p5"
            }
        }

class TokenRevokeInDB(BaseModel):
    """Schéma pour un token révoqué en base de données"""
    jti: str = Field(..., description="Identifiant unique du token")
    token_type: str = Field(..., description="Type de token (access, refresh)")
    user_id: int = Field(..., description="ID de l'utilisateur associé")
    revoked_at: datetime = Field(..., description="Date de révocation")
    expires_at: datetime = Field(..., description="Date d'expiration")
    
    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "jti": "2a4b6c8d0e1f3g5h7j9k0l1m2n3o4p5",
                "token_type": "access",
                "user_id": 1,
                "revoked_at": "2023-01-01T12:00:00",
                "expires_at": "2023-12-31T23:59:59"
            }
        }
