"""
Package principal de l'application Firewall
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .config import settings

app = FastAPI(
    title="Firewall Manager",
    description="Gestionnaire de pare-feu simple et puissant",
    version="1.0.0"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montage des fichiers statiques
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Import des routes
from .api import api_router
app.include_router(api_router, prefix="/api")

# Import des modèles de base de données
from .models import base
base.init_db()

# Import des vues
from .views import views
app.include_router(views.router)

# Gestion des erreurs
from .utils import exceptions
exceptions.register_handlers(app)
