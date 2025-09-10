"""
Gestion de la sécurité et de l'authentification avancée
"""
import os
import re
import time
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import jwt
import pyotp
from email_validator import EmailNotValidError, validate_email
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError
from passlib.context import CryptContext
from pydantic import EmailStr, ValidationError
from sqlalchemy.orm import Session

from app import crud, models, schemas
from app.core.config import settings
from app.db.session import get_db
from app.models import Log, LogCategory, LogLevel, User
from app.models.log import Log, LogCategory, LogLevel
from app.schemas.user import TokenData, UserCreate, UserUpdate, UserInDB
from app.schemas.token import Token, TokenPayload, TokenCreate, TokenRefresh
from app.core.logging import logger

logger = logging.getLogger(__name__)

# Configuration du hachage des mots de passe
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=settings.SECURITY_BCRYPT_ROUNDS
)

# Schéma OAuth2 pour l'authentification par token
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    scopes={
        "me": "Lire les informations sur votre propre compte",
        "users:read": "Lire les informations des utilisateurs",
        "users:write": "Modifier les informations des utilisateurs",
        "admin": "Accès administrateur complet",
    },
)

# Constantes de sécurité
TOTP_ISSUER = settings.PROJECT_NAME or "AI Firewall"
MAX_LOGIN_ATTEMPTS = getattr(settings, "MAX_LOGIN_ATTEMPTS", 5)  # Nombre maximum de tentatives avant verrouillage
ACCOUNT_LOCKOUT_DURATION = getattr(settings, "ACCOUNT_LOCKOUT_MINUTES", 15)  # Durée en minutes
RATE_LIMIT_WINDOW = getattr(settings, "RATE_LIMIT_WINDOW_SECONDS", 60)  # Fenêtre en secondes
RATE_LIMIT_MAX_REQUESTS = getattr(settings, "RATE_LIMIT_MAX_REQUESTS", 100)  # Requêtes max par fenêtre
TOKEN_EXPIRE_MINUTES = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 30)  # Durée de vie du token en minutes
REFRESH_TOKEN_EXPIRE_DAYS = getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)  # Durée de vie du refresh token

# Types de jetons JWT
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
TOKEN_TYPE_RESET_PASSWORD = "reset_password"
TOKEN_TYPE_VERIFY_EMAIL = "verify_email"

# Scopes par défaut
DEFAULT_SCOPES = ["me"]
ADMIN_SCOPES = ["admin"]

# Messages d'erreur
ERROR_INVALID_CREDENTIALS = "Identifiants invalides"
ERROR_ACCOUNT_LOCKED = "Compte temporairement verrouillé. Veuillez réessayer plus tard."
ERROR_RATE_LIMIT_EXCEEDED = "Trop de tentatives. Veuillez réessayer plus tard."
ERROR_INACTIVE_ACCOUNT = "Ce compte est inactif"
ERROR_INSUFFICIENT_PERMISSIONS = "Permissions insuffisantes pour effectuer cette action"
ERROR_TOKEN_EXPIRED = "Le jeton a expiré"
ERROR_TOKEN_INVALID = "Jeton invalide"
ERROR_ACCOUNT_NOT_VERIFIED = "Ce compte n'a pas été vérifié"
ERROR_ACCOUNT_ALREADY_EXISTS = "Un compte avec cet email ou ce nom d'utilisateur existe déjà"
ERROR_WEAK_PASSWORD = "Le mot de passe est trop faible"
ERROR_INVALID_EMAIL = "Adresse email invalide"
ERROR_INVALID_PHONE = "Numéro de téléphone invalide"
ERROR_INVALID_CSRF_TOKEN = "Jeton CSRF invalide"
ERROR_INVALID_2FA_CODE = "Code de vérification à deux facteurs invalide"
ERROR_2FA_REQUIRED = "Vérification à deux facteurs requise"
ERROR_2FA_ALREADY_ENABLED = "L'authentification à deux facteurs est déjà activée"
ERROR_2FA_NOT_ENABLED = "L'authentification à deux facteurs n'est pas activée"
ERROR_2FA_BACKUP_CODE_USED = "Ce code de secours a déjà été utilisé"
ERROR_2FA_BACKUP_CODE_INVALID = "Code de secours invalide"
ERROR_PASSWORD_TOO_COMMON = "Ce mot de passe est trop courant"
ERROR_PASSWORD_TOO_SHORT = "Le mot de passe doit contenir au moins 12 caractères"
ERROR_PASSWORD_NO_UPPER = "Le mot de passe doit contenir au moins une majuscule"
ERROR_PASSWORD_NO_LOWER = "Le mot de passe doit contenir au moins une minuscule"
ERROR_PASSWORD_NO_DIGIT = "Le mot de passe doit contenir au moins un chiffre"
ERROR_PASSWORD_NO_SPECIAL = "Le mot de passe doit contenir au moins un caractère spécial"

# Modèle pour les réponses d'erreur
class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
    field: Optional[str] = None

# Schéma pour le token bearer
security = HTTPBearer()

# Expressions régulières pour la validation
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$"
)
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")

# Exceptions personnalisées
class AuthError(HTTPException):
    """Classe de base pour les erreurs d'authentification"""
    def __init__(
        self, 
        status_code: int = status.HTTP_401_UNAUTHORIZED,
        detail: str = None,
        headers: Dict[str, str] = None,
        code: str = None
    ):
        if headers is None:
            headers = {"WWW-Authenticate": "Bearer"}
        
        if detail is None:
            detail = ERROR_INVALID_CREDENTIALS
            
        super().__init__(
            status_code=status_code,
            detail=detail,
            headers=headers
        )
        self.code = code or "authentication_failed"
        self.detail = detail
        self.status_code = status_code
        self.headers = headers


class InvalidCredentialsError(AuthError):
    """Erreur levée lorsque les identifiants sont invalides"""
    def __init__(self, detail: str = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail or ERROR_INVALID_CREDENTIALS,
            code="invalid_credentials"
        )


class InactiveUserError(AuthError):
    """Erreur levée lorsque l'utilisateur est inactif"""
    def __init__(self, detail: str = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail or ERROR_INACTIVE_ACCOUNT,
            code="inactive_account"
        )


class UnverifiedAccountError(AuthError):
    """Erreur levée lorsque le compte n'est pas vérifié"""
    def __init__(self, detail: str = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail or ERROR_ACCOUNT_NOT_VERIFIED,
            code="unverified_account"
        )


class AccountLockedError(AuthError):
    """Erreur levée lorsque le compte est verrouillé"""
    def __init__(self, lockout_until: datetime, detail: str = None):
        retry_after = int((lockout_until - datetime.utcnow()).total_seconds())
        headers = {"Retry-After": str(retry_after)}
        
        if detail is None:
            minutes = max(1, (retry_after + 59) // 60)  # Arrondi à la minute supérieure
            detail = f"Trop de tentatives échouées. Réessayez dans {minutes} minutes."
        
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers=headers,
            code="account_locked"
        )
        self.lockout_until = lockout_until


class RateLimitExceededError(AuthError):
    """Erreur levée lorsque le taux de requêtes est dépassé"""
    def __init__(self, retry_after: int, detail: str = None):
        headers = {"Retry-After": str(retry_after)}
        
        if detail is None:
            minutes = max(1, (retry_after + 59) // 60)  # Arrondi à la minute supérieure
            detail = f"Trop de requêtes. Réessayez dans {minutes} minutes."
        
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers=headers,
            code="rate_limit_exceeded"
        )
        self.retry_after = retry_after


class PermissionDeniedError(HTTPException):
    """Erreur levée lorsque l'utilisateur n'a pas les permissions nécessaires"""
    def __init__(self, required_scopes: List[str] = None, detail: str = None):
        if detail is None:
            if required_scopes:
                detail = f"Permissions requises: {', '.join(required_scopes)}"
            else:
                detail = ERROR_INSUFFICIENT_PERMISSIONS
        
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            headers={"WWW-Authenticate": f"Bearer scope=\"{' '.join(required_scopes or [])}\""}
        )
        self.required_scopes = required_scopes or []
        self.code = "permission_denied"


class TokenError(AuthError):
    """Erreur liée aux jetons JWT"""
    def __init__(self, detail: str = None, code: str = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail or ERROR_TOKEN_INVALID,
            code=code or "token_error"
        )


class TokenExpiredError(TokenError):
    """Erreur levée lorsque le jeton a expiré"""
    def __init__(self, detail: str = None):
        super().__init__(
            detail=detail or ERROR_TOKEN_EXPIRED,
            code="token_expired"
        )


class TokenRevokedError(TokenError):
    """Erreur levée lorsque le jeton a été révoqué"""
    def __init__(self, detail: str = None):
        super().__init__(
            detail=detail or "Token révoqué",
            code="token_revoked"
        )


class TwoFactorRequiredError(AuthError):
    """Erreur levée lorsqu'une authentification à deux facteurs est requise"""
    def __init__(self, temp_token: str, detail: str = None):
        super().__init__(
            status_code=status.HTTP_202_ACCEPTED,
            detail=detail or ERROR_2FA_REQUIRED,
            code="two_factor_required"
        )
        self.temp_token = temp_token


class TwoFactorCodeError(AuthError):
    """Erreur liée aux codes d'authentification à deux facteurs"""
    def __init__(self, detail: str, code: str = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            code=code or "two_factor_error"
        )


class PasswordValidationError(ValueError):
    """Erreur de validation de mot de passe"""
    def __init__(self, message: str, code: str = None, field: str = None):
        super().__init__(message)
        self.code = code or "password_validation_error"
        self.field = field


class CSRFError(AuthError):
    """Erreur liée à la validation CSRF"""
    def __init__(self, detail: str = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail or ERROR_INVALID_CSRF_TOKEN,
            code="csrf_validation_failed"
        )


# Configuration TOTP (2FA)
TOTP_ISSUER = settings.PROJECT_NAME
TOTP_INTERVAL = 30  # secondes
TOTP_DIGITS = 6
TOTP_ALGORITHM = "sha1"

# Fonctions utilitaires pour les mots de passe
def hash_password(password: str) -> str:
    """
    Hache un mot de passe en utilisant bcrypt.
    
    Args:
        password: Mot de passe en clair
        
    Returns:
        str: Mot de passe haché
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie qu'un mot de passe correspond à un hash.
    
    Args:
        plain_password: Mot de passe en clair
        hashed_password: Mot de passe haché
        
    Returns:
        bool: True si la vérification est réussie, False sinon
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du mot de passe: {str(e)}")
        return False


def generate_password_reset_token(email: str) -> str:
    """
    Génère un jeton de réinitialisation de mot de passe.
    
    Args:
        email: Email de l'utilisateur
        
    Returns:
        str: Jeton JWT
    """
    expires = datetime.utcnow() + timedelta(hours=1)
    to_encode = {
        "exp": expires,
        "sub": email,
        "type": TOKEN_TYPE_RESET_PASSWORD
    }
    
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )


def verify_password_reset_token(token: str) -> Optional[str]:
    """
    Vérifie un jeton de réinitialisation de mot de passe.
    
    Args:
        token: Jeton à vérifier
        
    Returns:
        Optional[str]: Email de l'utilisateur si le jeton est valide, None sinon
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        if payload.get("type") != TOKEN_TYPE_RESET_PASSWORD:
            return None
            
        return payload.get("sub")
    except JWTError:
        return None


# Fonctions pour les jetons JWT
def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    scopes: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> str:
    """
    Crée un jeton d'accès JWT.
    
    Args:
        subject: Identifiant de l'utilisateur
        expires_delta: Durée de validité du jeton
        scopes: Liste des scopes du jeton
        user_agent: User-Agent de la requête
        ip_address: Adresse IP du client
        
    Returns:
        str: Jeton JWT encodé
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": TOKEN_TYPE_ACCESS,
        "scopes": scopes or [],
        "jti": secrets.token_urlsafe(32),  # Identifiant unique du jeton
        "iat": datetime.utcnow()
    }
    
    if user_agent:
        to_encode["user_agent"] = user_agent
    if ip_address:
        to_encode["ip"] = ip_address
    
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )


def create_refresh_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> str:
    """
    Crée un jeton de rafraîchissement JWT.
    
    Args:
        subject: Identifiant de l'utilisateur
        expires_delta: Durée de validité du jeton
        user_agent: User-Agent de la requête
        ip_address: Adresse IP du client
        
    Returns:
        str: Jeton de rafraîchissement JWT encodé
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": TOKEN_TYPE_REFRESH,
        "jti": secrets.token_urlsafe(32),  # Identifiant unique du jeton
        "iat": datetime.utcnow()
    }
    
    if user_agent:
        to_encode["user_agent"] = user_agent
    if ip_address:
        to_encode["ip"] = ip_address
    
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )


def verify_token(token: str) -> Dict[str, Any]:
    """
    Vérifie et décode un jeton JWT.
    
    Args:
        token: Jeton JWT à vérifier
        
    Returns:
        Dict[str, Any]: Charge utile du jeton
        
    Raises:
        TokenExpiredError: Si le jeton a expiré
        TokenError: Si le jeton est invalide
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError()
    except JWTError as e:
        raise TokenError(f"Jeton invalide: {str(e)}")


# Fonctions pour l'authentification TOTP
def generate_totp_secret() -> str:
    """
    Génère une clé secrète pour l'authentification à deux facteurs.
    
    Returns:
        str: Clé secrète au format base32
    """
    return pyotp.random_base32()


def get_totp_uri(email: str, secret: str) -> str:
    """
    Génère une URI pour l'ajout à une application d'authentification.
    
    Args:
        email: Email de l'utilisateur
        secret: Clé secrète TOTP
        
    Returns:
        str: URI pour l'application d'authentification
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=TOTP_ISSUER
    )


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Vérifie un code TOTP.
    
    Args:
        secret: Clé secrète TOTP
        code: Code à vérifier
        
    Returns:
        bool: True si le code est valide, False sinon
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Tolère un décalage d'une période


# Fonctions pour la validation des données
def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Vérifie la force d'un mot de passe.
    
    Args:
        password: Mot de passe à valider
        
    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if len(password) < 12:
        return False, ERROR_PASSWORD_TOO_SHORT
    
    if not any(c.isupper() for c in password):
        return False, ERROR_PASSWORD_NO_UPPER
    
    if not any(c.islower() for c in password):
        return False, ERROR_PASSWORD_NO_LOWER
    
    if not any(c.isdigit() for c in password):
        return False, ERROR_PASSWORD_NO_DIGIT
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, ERROR_PASSWORD_NO_SPECIAL
    
    # Vérifie les mots de passe courants
    common_passwords = [
        'password', '123456', '123456789', '12345678', '12345',
        '1234567', '1234567890', 'qwerty', 'abc123', 'password1'
    ]
    
    if password.lower() in common_passwords:
        return False, ERROR_PASSWORD_TOO_COMMON
    
    return True, ""


def validate_email_format(email: str) -> bool:
    """
    Valide le format d'une adresse email.
    
    Args:
        email: Adresse email à valider
        
    Returns:
        bool: True si l'email est valide, False sinon
    """
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


# Fonctions pour la gestion des sessions
def create_session_cookie(
    response: Response,
    token: str,
    expires_in: int = TOKEN_EXPIRE_MINUTES * 60
) -> None:
    """
    Définit un cookie de session sécurisé.
    
    Args:
        response: Objet Response FastAPI
        token: Jeton de session
        expires_in: Durée de validité en secondes
    """
    secure = not settings.DEBUG
    samesite = "lax" if settings.DEBUG else "strict"
    
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        max_age=expires_in,
        httponly=True,
        secure=secure,
        samesite=samesite,
        domain=settings.SESSION_COOKIE_DOMAIN,
        path=settings.API_V1_STR
    )


def delete_session_cookie(response: Response) -> None:
    """
    Supprime le cookie de session.
    
    Args:
        response: Objet Response FastAPI
    """
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        domain=settings.SESSION_COOKIE_DOMAIN,
        path=settings.API_V1_STR
    )


# Fonctions pour la gestion des jetons CSRF
def generate_csrf_token() -> str:
    """
    Génère un jeton CSRF sécurisé.
    
    Returns:
        str: Jeton CSRF
    """
    return secrets.token_urlsafe(32)


def verify_csrf_token(
    request: Request,
    token: Optional[str] = None,
    header_name: str = "X-CSRF-Token"
) -> bool:
    """
    Vérifie un jeton CSRF.
    
    Args:
        request: Objet Request FastAPI
        token: Jeton CSRF (peut être dans le formulaire ou l'en-tête)
        header_name: Nom de l'en-tête CSRF
        
    Returns:
        bool: True si le jeton est valide, False sinon
    """
    if not settings.ENABLE_CSRF_PROTECTION:
        return True
    
    # Récupère le jeton CSRF de la session
    session_token = request.session.get("csrf_token")
    if not session_token:
        return False
    
    # Récupère le jeton CSRF de la requête
    request_token = (
        token or 
        request.headers.get(header_name) or 
        request.query_params.get("csrf_token")
    )
    
    if not request_token:
        return False
    
    # Compare les jetons de manière sécurisée contre les attaques temporelles
    return hmac.compare_digest(session_token, request_token)


# Dépendances FastAPI pour l'authentification
async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    request: Request = None
) -> User:
    """
    Dépendance FastAPI pour récupérer l'utilisateur actuellement authentifié.
    """
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = 'Bearer'
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les informations d'identification",
        headers={"WWW-Authenticate": authenticate_value},
    )
    
    try:
        payload = verify_token(token)
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
            
        token_scopes = payload.get("scopes", [])
        
        if security_scopes.scopes:
            for scope in security_scopes.scopes:
                if scope not in token_scopes:
                    raise PermissionDeniedError(security_scopes.scopes)
        
        user = db.query(User).filter(User.username == username).first()
        
        if user is None:
            raise credentials_exception
            
        if not user.is_active:
            raise InactiveUserError()
            
        # Vérifie si le jeton a été révoqué
        if user.token_version != payload.get("jti"):
            raise TokenRevokedError()
            
        # Enregistre l'accès réussi
        if request:
            await record_successful_login(db, user, request)
            
        return user
        
    except JWTError as e:
        logger.error(f"Erreur de validation du jeton: {str(e)}")
        raise credentials_exception


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dépendance pour récupérer l'utilisateur actif.
    """
    if not current_user.is_active:
        raise InactiveUserError()
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dépendance pour récupérer un superutilisateur.
    """
    if not current_user.is_superuser:
        raise PermissionDeniedError(["admin"])
    return current_user


# Fonctions utilitaires pour l'enregistrement des connexions
async def record_successful_login(
    db: Session,
    user: User,
    request: Request
) -> None:
    """
    Enregistre une connexion réussie.
    """
    try:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        # Met à jour la dernière connexion
        user.last_login = datetime.utcnow()
        user.last_login_ip = ip_address
        
        # Enregistre dans les logs
        log = Log(
            level=LogLevel.INFO,
            category=LogCategory.AUTH,
            message=f"Connexion réussie pour l'utilisateur {user.username}",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="login",
            object_id=str(user.id),
            object_type="user"
        )
        
        db.add(log)
        db.commit()
        
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement de la connexion: {str(e)}")
        db.rollback()


# Modèles de réponse d'erreur
class AuthError(HTTPException):
    """Classe de base pour les erreurs d'authentification"""
    def __init__(self, status_code: int, detail: str = None, headers: dict = None):
        if headers is None:
            headers = {}
        super().__init__(
            status_code=status_code,
            detail=detail or "Erreur d'authentification",
            headers=headers
        )
        self.code = "authentication_failed"


class RateLimitExceeded(AuthError):
    """Dépassement de la limite de taux"""
    def __init__(self, retry_after: int, detail: str = None):
        super().__init__(
            error=f"Trop de tentatives. Réessayez dans {retry_after} secondes.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS
        )
        self.retry_after = retry_after
        
class AccountLocked(AuthError):
    """Compte verrouillé après trop de tentatives échouées"""
    def __init__(self, locked_until: datetime):
        super().__init__(
            error=f"Compte verrouillé jusqu'à {locked_until.strftime('%Y-%m-%d %H:%M:%S')}",
            status_code=status.HTTP_403_FORBIDDEN
        )
        self.locked_until = locked_until


class InactiveUser(AuthError):
    """Utilisateur inactif"""
    def __init__(self):
        super().__init__(
            error="Ce compte utilisateur est désactivé",
            status_code=status.HTTP_403_FORBIDDEN
        )


class InvalidCredentials(AuthError):
    """Identifiants invalides"""
    def __init__(self):
        super().__init__(
            error="Nom d'utilisateur ou mot de passe incorrect",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )


class PermissionDenied(AuthError):
    """Permissions insuffisantes"""
    def __init__(self, required_scopes: List[str] = None):
        detail = "Pas les permissions requises"
        if required_scopes:
            detail = f"Permissions requises: {', '.join(required_scopes)}"
        
        headers = {"WWW-Authenticate": "Bearer"}
        if required_scopes:
            headers["WWW-Authenticate"] = f"Bearer scope=\"{' '.join(required_scopes)}\""
            
        super().__init__(
            error=detail,
            status_code=status.HTTP_403_FORBIDDEN,
            headers=headers
        )


class TokenError(AuthError):
    """Erreur de jeton générique"""
    def __init__(self, detail: str = "Jeton invalide"):
        super().__init__(
            error=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )


class TokenExpired(TokenError):
    """Jeton expiré"""
    def __init__(self):
        super().__init__(detail="Jeton expiré")


class TokenRevoked(TokenError):
    """Jeton révoqué"""
    def __init__(self):
        super().__init__(detail="Jeton révoqué")


class TwoFactorRequired(AuthError):
    """Authentification à deux facteurs requise"""
    def __init__(self):
        super().__init__(
            error="Authentification à deux facteurs requise",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )


class TwoFactorInvalid(AuthError):
    """Code d'authentification à deux facteurs invalide"""
    def __init__(self):
        super().__init__(
            error="Code d'authentification invalide",
            status_code=status.HTTP_400_BAD_REQUEST
        )


class PasswordValidationError(AuthError):
    """Erreur de validation de mot de passe"""
    def __init__(self, detail: str):
        super().__init__(
            error=detail,
            status_code=status.HTTP_400_BAD_REQUEST
        )


class CSRFValidationError(AuthError):
    """Erreur de validation CSRF"""
    def __init__(self):
        super().__init__(
            error="Échec de la validation CSRF",
            status_code=status.HTTP_403_FORBIDDEN
        )


class UserAlreadyExists(AuthError):
    """L'utilisateur existe déjà"""
    def __init__(self, field: str = "email"):
        super().__init__(
            error=f"Un utilisateur avec ce {field} existe déjà",
            status_code=status.HTTP_400_BAD_REQUEST
        )


class InvalidInput(AuthError):
    """Données d'entrée invalides"""
    def __init__(self, detail: str = "Données d'entrée invalides"):
        super().__init__(
            error=detail,
            status_code=status.HTTP_400_BAD_REQUEST
        )


class NotFound(AuthError):
    """Ressource non trouvée"""
    def __init__(self, resource: str = "ressource"):
        super().__init__(
            error=f"{resource.capitalize()} non trouvée",
            status_code=status.HTTP_404_NOT_FOUND
        )


class InternalServerError(AuthError):
    """Erreur interne du serveur"""
    def __init__(self):
        super().__init__(
            error="Une erreur interne est survenue",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class ServiceUnavailable(AuthError):
    """Service temporairement indisponible"""
    def __init__(self, retry_after: int = 60):
        super().__init__(
            error="Service temporairement indisponible",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": str(retry_after)}
        )
        self.retry_after = retry_after

class AccountLocked(AuthError):
    """Compte verrouillé"""
    def __init__(self, locked_until: datetime):
        super().__init__(
            error=f"Compte temporairement verrouillé jusqu'à {locked_until}",
            status_code=status.HTTP_423_LOCKED
        )
        self.locked_until = locked_until

class InvalidCredentials(AuthError):
    """Identifiants invalides"""
    def __init__(self):
        super().__init__(
            error="Nom d'utilisateur ou mot de passe incorrect",
            status_code=status.HTTP_401_UNAUTHORIZED
        )

class TokenError(AuthError):
    """Erreur de token JWT"""
    def __init__(self, error: str = "Token invalide ou expiré"):
        super().__init__(error=error, status_code=status.HTTP_401_UNAUTHORIZED)

class PermissionDenied(AuthError):
    """Permissions insuffisantes"""
    def __init__(self, required_scopes: List[str] = None):
        msg = "Permissions insuffisantes"
        if required_scopes:
            msg += f" (scopes requis: {', '.join(required_scopes)})"
        super().__init__(error=msg, status_code=status.HTTP_403_FORBIDDEN)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie si le mot de passe en clair correspond au hachage stocké.
    
    Args:
        plain_password: Mot de passe en clair fourni par l'utilisateur
        hashed_password: Hachage stocké dans la base de données
        
    Returns:
        bool: True si le mot de passe correspond, False sinon
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du mot de passe: {str(e)}")
        return False

def get_password_hash(password: str) -> str:
    """
    Génère un hachage sécurisé à partir d'un mot de passe en clair.
    
    Args:
        password: Mot de passe en clair
        
    Returns:
        str: Hachage sécurisé du mot de passe
    """
    return pwd_context.hash(password)

def generate_secure_password(length: int = 16) -> str:
    """
    Génère un mot de passe sécurisé aléatoire.
    
    Args:
        length: Longueur du mot de passe à générer
        
    Returns:
        str: Mot de passe sécurisé
    """
    if length < 12:
        raise ValueError("La longueur minimale du mot de passe doit être de 12 caractères")
    
    # Caractères à utiliser pour générer le mot de passe
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Assure qu'on a au moins un caractère de chaque type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Remplit le reste du mot de passe avec des caractères aléatoires
    all_chars = lowercase + uppercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Mélange les caractères pour plus de sécurité
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def is_password_strong(password: str) -> bool:
    """
    Vérifie si un mot de passe est suffisamment fort.
    
    Un mot de passe est considéré comme fort s'il contient :
    - Au moins 12 caractères
    - Au moins une minuscule
    - Au moins une majuscule
    - Au moins un chiffre
    - Au moins un caractère spécial
    
    Args:
        password: Mot de passe à vérifier
        
    Returns:
        bool: True si le mot de passe est fort, False sinon
    """
    if len(password) < 12:
        return False
    
    if not re.search(r'[a-z]', password):
        return False
    
    if not re.search(r'[A-Z]', password):
        return False
    
    if not re.search(r'[0-9]', password):
        return False
    
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    
    return True

def create_access_token(
    subject: Union[str, Any], 
    expires_delta: Optional[timedelta] = None,
    scopes: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> str:
    """
    Crée un token JWT avec une date d'expiration et des métadonnées.
    
    Args:
        subject: Identifiant de l'utilisateur (sujet du token)
        expires_delta: Durée de validité du token
        scopes: Liste des scopes accordés
        user_agent: User-Agent de la requête
        ip_address: Adresse IP de la requête
        
    Returns:
        str: Token JWT encodé
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    # Crée le payload du token
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(32),  # Identifiant unique du token
    }
    
    # Ajoute des métadonnées supplémentaires
    if scopes:
        to_encode["scopes"] = scopes
    
    if user_agent:
        to_encode["user_agent"] = user_agent
    
    if ip_address:
        to_encode["ip"] = ip_address
    
    # Signe le token avec la clé secrète
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt

def create_refresh_token(
    user_id: int,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crée un token de rafraîchissement.
    
    Args:
        user_id: ID de l'utilisateur
        expires_delta: Durée de validité du token
        
    Returns:
        str: Token de rafraîchissement JWT
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
    
    to_encode = {
        "exp": expire,
        "sub": str(user_id),
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
        "jti": secrets.token_urlsafe(32),
    }
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.REFRESH_SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt

def verify_token(token: str, is_refresh: bool = False) -> Dict[str, Any]:
    """
    Vérifie et décode un token JWT.
    
    Args:
        token: Token JWT à vérifier
        is_refresh: Si True, utilise la clé de rafraîchissement
        
    Returns:
        Dict: Payload décodé du token
        
    Raises:
        TokenError: Si le token est invalide ou expiré
    """
    try:
        secret_key = settings.REFRESH_SECRET_KEY if is_refresh else settings.SECRET_KEY
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "iat", "sub"]}
        )
        return payload
    except ExpiredSignatureError:
        raise TokenError("Token expiré")
    except JWTError as e:
        raise TokenError(f"Token invalide: {str(e)}")

def get_token_payload(token: str) -> TokenPayload:
    """
    Récupère et valide le payload d'un token JWT.
    
    Args:
        token: Token JWT
        
    Returns:
        TokenPayload: Données du token validées
        
    Raises:
        HTTPException: Si le token est invalide
    """
    try:
        payload = verify_token(token)
        token_data = TokenPayload(
            sub=payload.get("sub"),
            exp=payload.get("exp"),
            iat=payload.get("iat"),
            jti=payload.get("jti"),
            scopes=payload.get("scopes", []),
            user_agent=payload.get("user_agent"),
            ip=payload.get("ip")
        )
        return token_data
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

async def authenticate_user(
    db: Session, 
    username: str, 
    password: str,
    request: Optional[Request] = None
) -> Optional[User]:
    """
    Authentifie un utilisateur avec son nom d'utilisateur et son mot de passe.
    
    Args:
        db: Session de base de données
        username: Nom d'utilisateur
        password: Mot de passe en clair
        request: Objet Request FastAPI (optionnel, pour le logging)
        
    Returns:
        User: Utilisateur authentifié ou None
        
    Raises:
        AccountLocked: Si le compte est verrouillé
        RateLimitExceeded: Si le taux de tentatives est dépassé
    """
    # Vérifie d'abord si l'utilisateur est verrouillé
    await check_account_lockout(db, username, request)
    
    # Récupère l'utilisateur depuis la base de données
    user = db.query(User).filter(
        (User.username == username) | (User.email == username)
    ).first()
    
    # Vérifie si l'utilisateur existe et le mot de passe est correct
    if not user or not verify_password(password, user.hashed_password):
        # Enregistre l'échec de connexion
        await record_failed_login_attempt(db, username, request)
        return None
    
    # Réinitialise le compteur d'échecs en cas de succès
    await reset_failed_login_attempts(db, username)
    
    return user

async def check_account_lockout(db: Session, username: str, request: Optional[Request] = None) -> None:
    """
    Vérifie si le compte est verrouillé en raison de trop nombreuses tentatives échouées.
    
    Args:
        db: Session de base de données
        username: Nom d'utilisateur
        request: Objet Request FastAPI (optionnel, pour le logging)
        
    Raises:
        AccountLocked: Si le compte est verrouillé
    """
    # Récupère les tentatives d'échec récentes
    lockout_time = datetime.utcnow() - timedelta(minutes=settings.ACCOUNT_LOCKOUT_DURATION)
    
    failed_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.username == username,
        LoginAttempt.success == False,
        LoginAttempt.created_at > lockout_time
    ).order_by(LoginAttempt.created_at.desc()).all()
    
    # Vérifie si le nombre maximal de tentatives a été atteint
    if len(failed_attempts) >= settings.MAX_LOGIN_ATTEMPTS:
        # Vérifie si la période de verrouillage est écoulée
        last_attempt = failed_attempts[0].created_at
        lockout_until = last_attempt + timedelta(minutes=settings.ACCOUNT_LOCKOUT_DURATION)
        
        if datetime.utcnow() < lockout_until:
            raise AccountLocked(lockout_until)
        else:
            # Réinitialise les tentatives si la période de verrouillage est écoulée
            await reset_failed_login_attempts(db, username)
    
    # Vérifie le taux de requêtes
    await check_rate_limit(request)

async def record_failed_login_attempt(
    db: Session, 
    username: str, 
    request: Optional[Request] = None
) -> None:
    """
    Enregistre une tentative de connexion échouée.
    
    Args:
        db: Session de base de données
        username: Nom d'utilisateur
        request: Objet Request FastAPI (optionnel, pour le logging)
    """
    try:
        ip_address = request.client.host if request and request.client else None
        user_agent = request.headers.get('user-agent') if request else None
        
        attempt = LoginAttempt(
            username=username,
            success=False,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.add(attempt)
        db.commit()
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement de la tentative de connexion échouée: {str(e)}")
        db.rollback()

async def reset_failed_login_attempts(db: Session, username: str) -> None:
    """
    Réinitialise le compteur de tentatives de connexion échouées.
    
    Args:
        db: Session de base de données
        username: Nom d'utilisateur
    """
    try:
        # Supprime les tentatives d'échec précédentes
        db.query(LoginAttempt).filter(
            LoginAttempt.username == username,
            LoginAttempt.success == False
        ).delete()
        
        # Enregistre une tentative réussie
        attempt = LoginAttempt(
            username=username,
            success=True
        )
        
        db.add(attempt)
        db.commit()
    except Exception as e:
        logger.error(f"Erreur lors de la réinitialisation des tentatives de connexion: {str(e)}")
        db.rollback()

async def check_rate_limit(request: Optional[Request] = None) -> None:
    """
    Vérifie si le taux de requêtes n'est pas dépassé.
    
    Args:
        request: Objet Request FastAPI
        
    Raises:
        RateLimitExceeded: Si le taux de requêtes est dépassé
    """
    if not request:
        return
    
    # Implémentation simplifiée - à remplacer par un système de rate limiting plus robuste
    # comme FastAPI-Limiter ou Redis pour la production
    ip_address = request.client.host if request.client else 'unknown'
    cache_key = f"rate_limit:{ip_address}"
    
    # Ici, vous devriez utiliser un cache comme Redis
    # Ceci est une implémentation simplifiée à des fins d'illustration
    current_time = time.time()
    window_start = current_time - settings.RATE_LIMIT_WINDOW
    
    # Récupère les timestamps des requêtes précédentes
    # Dans une implémentation réelle, utilisez un cache partagé comme Redis
    request_timestamps = getattr(request.app.state, 'rate_limits', {}).get(cache_key, [])
    
    # Filtre les requêtes dans la fenêtre de temps actuelle
    request_timestamps = [ts for ts in request_timestamps if ts > window_start]
    
    # Vérifie si le nombre maximal de requêtes est dépassé
    if len(request_timestamps) >= settings.RATE_LIMIT_MAX_REQUESTS:
        retry_after = int(window_start + settings.RATE_LIMIT_WINDOW - current_time)
        raise RateLimitExceeded(retry_after)
    
    # Ajoute la requête actuelle
    request_timestamps.append(current_time)
    
    # Met à jour le cache (dans une implémentation réelle, utilisez un cache partagé)
    if not hasattr(request.app.state, 'rate_limits'):
        request.app.state.rate_limits = {}
    request.app.state.rate_limits[cache_key] = request_timestamps

async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    request: Request = None
) -> User:
    """
    Récupère l'utilisateur actuellement connecté et vérifie les scopes requis.
    
    Args:
        security_scopes: Scopes de sécurité requis
        token: Token JWT
        db: Session de base de données
        request: Objet Request FastAPI
        
    Returns:
        User: Utilisateur authentifié
        
    Raises:
        HTTPException: Si l'authentification ou l'autorisation échoue
    """
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = 'Bearer'
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les identifiants",
        headers={"WWW-Authenticate": authenticate_value},
    )
    
    try:
        # Vérifie et décode le token
        payload = verify_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        # Récupère les scopes du token
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(username=username, scopes=token_scopes)
        
        # Vérifie les scopes requis
        if security_scopes.scopes:
            for scope in security_scopes.scopes:
                if scope not in token_scopes:
                    raise PermissionDenied(security_scopes.scopes)
        
    except (JWTError, ValidationError) as e:
        logger.error(f"Erreur de validation du token: {str(e)}")
        raise credentials_exception
    
    # Récupère l'utilisateur depuis la base de données
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    
    # Vérifie si le compte est actif
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Compte inactif")
    
    # Vérifie si le token a été révoqué
    if user.token_version != payload.get("jti"):
        raise TokenError("Token révoqué")
    
    # Enregistre l'accès réussi (pour audit)
    await record_successful_access(db, user, request)
    
    return user

async def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=[])
) -> User:
    """
    Vérifie que l'utilisateur est actif.
    
    Args:
        current_user: Utilisateur actuel
        
    Returns:
        User: Utilisateur actif
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Compte inactif")
    return current_user

async def get_current_superuser(
    current_user: User = Security(get_current_user, scopes=["admin"])
) -> User:
    """
    Vérifie que l'utilisateur est un superutilisateur.
    
    Args:
        current_user: Utilisateur actuel
        
    Returns:
        User: Superutilisateur
    """
    if not current_user.is_superuser:
        raise PermissionDenied(["admin"])
    return current_user

async def record_successful_access(
    db: Session,
    user: User,
    request: Optional[Request] = None
) -> None:
    """
    Enregistre un accès réussi à l'API.
    
    Args:
        db: Session de base de données
        user: Utilisateur
        request: Objet Request FastAPI (optionnel, pour le logging)
    """
    try:
        ip_address = request.client.host if request and request.client else None
        user_agent = request.headers.get('user-agent') if request else None
        
        # Met à jour la dernière connexion de l'utilisateur
        user.last_login = datetime.utcnow()
        user.last_login_ip = ip_address
        
        # Enregistre l'accès dans les journaux
        log = Log(
            level=LogLevel.INFO,
            category=LogCategory.AUTH,
            message=f"Connexion réussie pour l'utilisateur {user.username}",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="login",
            object_id=str(user.id),
            object_type="user"
        )
        
        db.add(log)
        db.commit()
        db.refresh(user)
        
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement de l'accès: {str(e)}")
        db.rollback()

def has_required_scopes(
    required_scopes: List[str],
    token: str = Depends(oauth2_scheme)
) -> bool:
    """
    Vérifie si le token a les scopes requis.
    
    Args:
        required_scopes: Liste des scopes requis
        token: Token JWT
        
    Returns:
        bool: True si les scopes sont présents, False sinon
    """
    try:
        payload = verify_token(token)
        token_scopes = payload.get("scopes", [])
        
        # Si aucun scope requis, l'accès est autorisé
        if not required_scopes:
            return True
            
        # Vérifie que tous les scopes requis sont présents
        return all(scope in token_scopes for scope in required_scopes)
        
    except (JWTError, ValidationError):
        return False

def get_authorization_scheme_param(authorization_header: str) -> Tuple[str, str]:
    """
    Extrait le schéma et la valeur du token d'un en-tête d'autorisation.
    
    Args:
        authorization_header: En-tête d'autorisation
        
    Returns:
        Tuple[str, str]: (schéma, token)
    """
    if not authorization_header:
        return "", ""
    
    parts = authorization_header.split()
    
    if len(parts) == 1:
        return "", parts[0]
    elif len(parts) == 2:
        return parts[0], parts[1]
    else:
        return "", ""

def verify_csrf_token(
    request: Request,
    csrf_token: Optional[str] = None,
    csrf_header: str = "X-CSRF-Token"
) -> bool:
    """
    Vérifie un jeton CSRF.
    
    Args:
        request: Objet Request FastAPI
        csrf_token: Jeton CSRF (peut être dans le formulaire ou l'en-tête)
        csrf_header: Nom de l'en-tête CSRF
        
    Returns:
        bool: True si le jeton est valide, False sinon
    """
    if not settings.ENABLE_CSRF_PROTECTION:
        return True
    
    # Récupère le jeton CSRF de la session
    session_csrf_token = request.session.get("csrf_token")
    if not session_csrf_token:
        return False
    
    # Récupère le jeton CSRF de la requête
    request_csrf_token = (
        csrf_token or 
        request.headers.get(csrf_header) or 
        request.query_params.get("csrf_token")
    )
    
    if not request_csrf_token:
        return False
    
    # Compare les jetons de manière sécurisée contre les attaques temporelles
    return hmac.compare_digest(session_csrf_token, request_csrf_token)

def generate_csrf_token() -> str:
    """
    Génère un jeton CSRF sécurisé.
    
    Returns:
        str: Jeton CSRF
    """
    return secrets.token_urlsafe(32)

def validate_email_address(email: str) -> bool:
    """
    Valide une adresse email.
    
    Args:
        email: Adresse email à valider
        
    Returns:
        bool: True si l'email est valide, False sinon
    """
    try:
        # Valide l'email avec email-validator
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

def validate_phone_number(phone: str, country_code: str = "FR") -> bool:
    """
    Valide un numéro de téléphone.
    
    Args:
        phone: Numéro de téléphone à valider
        country_code: Code pays à 2 lettres (par défaut: FR)
        
    Returns:
        bool: True si le numéro est valide, False sinon
    """
    try:
        parsed_number = phonenumbers.parse(phone, country_code)
        return phonenumbers.is_valid_number(parsed_number)
    except phonenumbers.NumberParseException:
        return False

def sanitize_input(input_string: str, allowed_tags: list = None) -> str:
    """
    Nettoie une chaîne de caractères pour prévenir les attaques XSS.
    
    Args:
        input_string: Chaîne à nettoyer
        allowed_tags: Liste des balises HTML autorisées (par défaut: aucune)
        
    Returns:
        str: Chaîne nettoyée
    """
    if not input_string:
        return ""
    
    # Échappe les caractères spéciaux HTML
    import html
    cleaned = html.escape(input_string)
    
    # Réautorise certaines balises si spécifiées
    if allowed_tags:
        for tag in allowed_tags:
            cleaned = cleaned.replace(f'&lt;{tag}&gt;', f'<{tag}>')
            cleaned = cleaned.replace(f'&lt;/{tag}&gt;', f'</{tag}>')
    
    return cleaned

def generate_totp_secret() -> str:
    """
    Génère une clé secrète pour l'authentification à deux facteurs (TOTP).
    
    Returns:
        str: Clé secrète au format base32
    """
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str) -> str:
    """
    Génère une URI pour l'ajout à une application d'authentification.
    
    Args:
        secret: Clé secrète TOTP
        email: Email de l'utilisateur
        
    Returns:
        str: URI pour l'application d'authentification
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=TOTP_ISSUER
    )

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Vérifie un code TOTP.
    
    Args:
        secret: Clé secrète TOTP
        code: Code à vérifier
        
    Returns:
        bool: True si le code est valide, False sinon
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Tolère un décalage d'une période

def generate_secure_token(length: int = 32) -> str:
    """
    Génère un jeton sécurisé aléatoire.
    
    Args:
        length: Longueur du jeton en octets
        
    Returns:
        str: Jeton sécurisé encodé en base64
    """
    if length < 16:
        raise ValueError("La longueur minimale du jeton est de 16 octets")
    
    return secrets.token_urlsafe(length)

def hash_data(data: str, algorithm: str = 'sha256') -> str:
    """
    Calcule le hachage d'une donnée.
    
    Args:
        data: Donnée à hacher
        algorithm: Algorithme de hachage (sha256, sha512, etc.)
        
    Returns:
        str: Hachage hexadécimal de la donnée
    """
    hash_func = hashlib.new(algorithm)
    hash_func.update(data.encode('utf-8'))
    return hash_func.hexdigest()

def generate_api_key(prefix: str = "api") -> str:
    """
    Génère une clé API sécurisée.
    
    Args:
        prefix: Préfixe pour la clé API
        
    Returns:
        str: Clé API au format prefix_xxxxx_yyyyy
    """
    random_part = secrets.token_urlsafe(32)
    return f"{prefix}_{random_part}"

def verify_api_key(api_key: str, hashed_api_key: str) -> bool:
    """
    Vérifie une clé API.
    
    Args:
        api_key: Clé API en clair
        hashed_api_key: Hachage de la clé API stocké en base
        
    Returns:
        bool: True si la clé est valide, False sinon
    """
    return pwd_context.verify(api_key, hashed_api_key)

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Vérifie la force d'un mot de passe et retourne des conseils d'amélioration.
    
    Args:
        password: Mot de passe à évaluer
        
    Returns:
        tuple: (is_valid, message)
    """
    if len(password) < 12:
        return False, "Le mot de passe doit contenir au moins 12 caractères"
    
    if not any(c.islower() for c in password):
        return False, "Le mot de passe doit contenir au moins une minuscule"
    
    if not any(c.isupper() for c in password):
        return False, "Le mot de passe doit contenir au moins une majuscule"
    
    if not any(c.isdigit() for c in password):
        return False, "Le mot de passe doit contenir au moins un chiffre"
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial"
    
    # Vérifie les séquences courantes
    common_sequences = [
        '123456', 'password', 'azerty', 'qwerty', '111111', '000000',
        'admin', 'welcome', 'sunshine', 'iloveyou', '123123', '123456789',
        'football', 'princess', 'qwertyuiop', '654321', 'superman', '1q2w3e4r'
    ]
    
    lower_pwd = password.lower()
    if any(seq in lower_pwd for seq in common_sequences):
        return False, "Le mot de passe contient une séquence trop courante"
    
    return True, "Mot de passe sécurisé"

def generate_password_reset_token(user_id: int, expires_minutes: int = 30) -> str:
    """
    Génère un jeton de réinitialisation de mot de passe.
    
    Args:
        user_id: ID de l'utilisateur
        expires_minutes: Durée de validité en minutes
        
    Returns:
        str: Jeton JWT de réinitialisation
    """
    expires = datetime.utcnow() + timedelta(minutes=expires_minutes)
    
    payload = {
        "sub": str(user_id),
        "exp": expires,
        "type": "password_reset"
    }
    
    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )

def verify_password_reset_token(token: str) -> Optional[int]:
    """
    Vérifie un jeton de réinitialisation de mot de passe.
    
    Args:
        token: Jeton à vérifier
        
    Returns:
        Optional[int]: ID de l'utilisateur si le jeton est valide, None sinon
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        if payload.get("type") != "password_reset":
            return None
            
        return int(payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        return None

def get_client_ip(request: Request) -> str:
    """
    Récupère l'adresse IP du client à partir de la requête.
    
    Args:
        request: Objet Request FastAPI
        
    Returns:
        str: Adresse IP du client
    """
    if not request.client:
        return "unknown"
    
    # Vérifie les en-têtes de proxy courants
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Prend la première adresse de la liste
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host

def get_user_agent(request: Request) -> str:
    """
    Récupère le User-Agent de la requête.
    
    Args:
        request: Objet Request FastAPI
        
    Returns:
        str: User-Agent ou chaîne vide si non disponible
    """
    return request.headers.get("user-agent", "")
