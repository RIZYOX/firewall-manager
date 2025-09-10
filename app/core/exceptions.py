"""
Gestion des exceptions personnalisées
"""
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.responses import JSONResponse
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class AppException(Exception):
    """Exception de base de l'application"""
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: str = "Une erreur inattendue s'est produite",
        error_code: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        self.status_code = status_code
        self.detail = detail
        self.error_code = error_code or f"ERR-{status_code}"
        self.extra = extra or {}
        super().__init__(detail)

class NotFoundException(AppException):
    """Exception pour les ressources non trouvées"""
    def __init__(self, resource: str, id: Any):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} avec l'ID {id} non trouvé",
            error_code="NOT_FOUND"
        )

class UnauthorizedException(AppException):
    """Exception pour les accès non autorisés"""
    def __init__(self, detail: str = "Authentification requise"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="UNAUTHORIZED"
        )

class ForbiddenException(AppException):
    """Exception pour les accès interdits"""
    def __init__(self, detail: str = "Accès refusé"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            error_code="FORBIDDEN"
        )

class BadRequestException(AppException):
    """Exception pour les requêtes incorrectes"""
    def __init__(self, detail: str = "Requête incorrecte"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            error_code="BAD_REQUEST"
        )

class ConflictException(AppException):
    """Exception pour les conflits de ressources"""
    def __init__(self, detail: str = "Conflit détecté"):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
            error_code="CONFLICT"
        )

async def http_exception_handler(request: Request, exc: HTTPException):
    """Gestionnaire d'erreurs HTTP"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": getattr(exc, "error_code", f"HTTP_{exc.status_code}"),
            "path": request.url.path
        }
    )

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Gestionnaire d'erreurs de validation"""
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"][1:])  # Ignore le premier élément (généralement 'body')
        errors.append({
            "field": field or "body",
            "message": error["msg"],
            "type": error["type"]
        })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Erreur de validation",
            "error_code": "VALIDATION_ERROR",
            "errors": errors
        }
    )

async def app_exception_handler(request: Request, exc: AppException):
    """Gestionnaire d'erreurs personnalisées"""
    logger.error(
        f"Erreur {exc.status_code}: {exc.detail}",
        extra={"error": exc.detail, "error_code": exc.error_code, "extra": exc.extra}
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": exc.error_code,
            "extra": exc.extra
        }
    )

async def unhandled_exception_handler(request: Request, exc: Exception):
    """Gestionnaire d'erreurs non gérées"""
    logger.exception("Erreur non gérée")
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Une erreur inattendue s'est produite",
            "error_code": "INTERNAL_SERVER_ERROR"
        }
    )

def register_handlers(app):
    """Enregistre les gestionnaires d'erreurs dans l'application FastAPI"""
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    
    return app
