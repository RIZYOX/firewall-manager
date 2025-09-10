"""
Dépendances de l'API
"""
from typing import Generator, Optional, List, Union, Dict, Any
from fastapi import Depends, HTTPException, status, Security, Request
from fastapi.security import OAuth2PasswordBearer, SecurityScopes, APIKeyHeader, APIKeyQuery
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.db.session import SessionLocal
from app.models.user import User
from app.schemas.token import TokenData, TokenPayload
from app.schemas.user import UserInDB, UserCreate, UserUpdate, UserInResponse

# Schéma d'authentification OAuth2 avec mot de passe
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_PREFIX}/auth/login",
    scopes={
        "me": "Lire les informations sur l'utilisateur actuel.",
        "users:read": "Lire les informations des utilisateurs.",
        "users:write": "Créer et mettre à jour les utilisateurs.",
        "users:delete": "Supprimer les utilisateurs.",
        "rules:read": "Lire les règles de pare-feu.",
        "rules:write": "Créer et mettre à jour les règles de pare-feu.",
        "rules:delete": "Supprimer les règles de pare-feu.",
        "system:read": "Lire les informations système.",
        "system:write": "Modifier les paramètres système.",
        "backup:read": "Lire les sauvegardes.",
        "backup:write": "Créer et restaurer des sauvegardes.",
        "backup:delete": "Supprimer des sauvegardes.",
        "admin": "Accès administrateur complet.",
    }
)

# En-têtes d'API
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

def get_db() -> Generator:
    """Fournit une session de base de données"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Récupère l'utilisateur actuel à partir du token JWT"""
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les identifiants",
        headers={"WWW-Authenticate": authenticate_value},
    )
    
    try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise credentials_exception
    
    user = db.query(User).filter(User.id == token_data.sub).first()
    if user is None:
        raise credentials_exception
    
    # Vérifier les scopes
    if security_scopes.scopes and not token_data.scopes:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Pas les permissions nécessaires",
            headers={"WWW-Authenticate": authenticate_value},
        )
    
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission manquante: {scope}",
                headers={"WWW-Authenticate": authenticate_value},
            )
    
    return user

def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=[])
) -> User:
    """Vérifie que l'utilisateur est actif"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Utilisateur inactif")
    return current_user

def get_current_active_superuser(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Vérifie que l'utilisateur est un superutilisateur"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="L'utilisateur n'a pas les privilèges suffisants",
        )
    return current_user

def get_api_key(
    api_key_header: str = Security(api_key_header),
    api_key_query: str = Security(api_key_query),
) -> str:
    """Récupère et valide la clé API"""
    # Vérifier d'abord l'en-tête, puis le paramètre de requête
    api_key = api_key_header or api_key_query
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API manquante",
        )
    
    # Ici, vous devriez vérifier la clé API dans la base de données
    # Pour l'instant, nous utilisons une vérification simple
    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clé API invalide",
        )
    
    return api_key

def get_pagination_params(
    skip: int = 0,
    limit: int = 100,
) -> Dict[str, int]:
    """Paramètres de pagination par défaut"""
    # Limiter le nombre maximum d'éléments par page
    if limit > 1000:
        limit = 1000
    return {"skip": skip, "limit": limit}

def get_ordering_params(
    order_by: str = "created_at",
    order: str = "desc",
    allowed_fields: list = None
) -> Dict[str, Any]:
    """Paramètres de tri"""
    # Valider le champ de tri
    if allowed_fields and order_by not in allowed_fields:
        order_by = "created_at"
    
    # Valider la direction du tri
    order = order.lower()
    if order not in ["asc", "desc"]:
        order = "desc"
    
    return {"order_by": order_by, "order": order}

def get_remote_ip(request: Request) -> str:
    """Récupère l'adresse IP du client"""
    if "x-forwarded-for" in request.headers:
        # En cas de proxy, prendre la première adresse
        return request.headers["x-forwarded-for"].split(",")[0]
    return request.client.host if request.client else "0.0.0.0"
