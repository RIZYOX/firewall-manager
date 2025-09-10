"""
Point d'entrée principal de l'application
"""
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
from pathlib import Path

from app.core.config import settings
from app.core.middleware import setup_middleware
from app.core.logging import setup_logging
from app.db.session import init_db, create_tables
from app.api import api_router
from app.views import views

# Configuration du logging
setup_logging()
logger = logging.getLogger(__name__)

def create_application() -> FastAPI:
    """Crée et configure l'application FastAPI"""
    # Création de l'application
    app = FastAPI(
        title=settings.APP_NAME,
        description="Pare-feu simple avec interface web",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )
    
    # Configuration CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Configuration des middlewares personnalisés
    setup_middleware(app)
    
    # Montage des fichiers statiques
    static_dir = Path(__file__).parent / "app" / "static"
    os.makedirs(static_dir, exist_ok=True)
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Montage des routes de l'API
    app.include_router(api_router, prefix="/api")
    
    # Montage des vues
    app.include_router(views.router)
    
    # Route de base
    @app.get("/")
    async def root():
        return {"message": "Bienvenue sur Firewall Manager"}
    
    # Route de santé
    @app.get("/health")
    async def health_check():
        return {"status": "ok"}
    
    return app

# Création de l'application
app = create_application()

# Initialisation de la base de données au démarrage
@app.on_event("startup")
async def startup_event():
    """Actions à effectuer au démarrage de l'application"""
    logger.info("Démarrage de l'application...")
    
    # Crée les tables si elles n'existent pas
    create_tables()
    
    # Initialise la base de données avec des données par défaut
    init_db()
    
    logger.info("Application démarrée avec succès")

# Point d'entrée principal
if __name__ == "__main__":
    # Lancement du serveur avec auto-reload en développement
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info" if settings.DEBUG else "warning"
    )
