"""
Middleware personnalisé
"""
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp
import logging

logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware pour le logging des requêtes"""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Ignore les requêtes pour les fichiers statics
        if request.url.path.startswith("/static"):
            return await call_next(request)
        
        # Enregistre le début de la requête
        start_time = time.time()
        
        # Informations de base sur la requête
        client_host = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        query_params = str(request.query_params) if request.query_params else ""
        
        # Log de la requête entrante
        logger.info(
            f"Requête entrante: {method} {path}?{query_params} from {client_host}"
        )
        
        try:
            # Passe à la suite du traitement
            response = await call_next(request)
            
            # Calcule le temps de traitement
            process_time = time.time() - start_time
            
            # Log de la réponse
            logger.info(
                f"Réponse: {method} {path} - {response.status_code} "
                f"en {process_time:.4f}s"
            )
            
            # Ajoute le temps de traitement dans les en-têtes
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            # En cas d'erreur non gérée
            process_time = time.time() - start_time
            logger.error(
                f"Erreur lors du traitement de {method} {path}: {str(e)}",
                exc_info=True
            )
            raise

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware pour les en-têtes de sécurité"""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        
        # Ajoute les en-têtes de sécurité
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        
        # HSTS - Uniquement en HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response

class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Middleware pour la gestion des erreurs"""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
        except Exception as e:
            # Log l'erreur
            logger.error(f"Erreur non gérée: {str(e)}", exc_info=True)
            
            # Renvoie une réponse d'erreur générique
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=500,
                content={"detail": "Une erreur interne est survenue"}
            )

def setup_middleware(app: ASGIApp):
    """Configure les middlewares de l'application"""
    # Désactive les middlewares intégrés de FastAPI
    app.middleware_stack = None
    
    # Ajoute les middlewares personnalisés
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ErrorHandlerMiddleware)
    
    return app
