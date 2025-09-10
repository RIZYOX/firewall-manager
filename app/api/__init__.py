"""
Routes de l'API
"""
from fastapi import APIRouter
from .endpoints import auth, rules, system

api_router = APIRouter()

# Inclusion des routes
def include_routers():
    api_router.include_router(auth.router, prefix="/auth", tags=["Authentification"])
    api_router.include_router(rules.router, prefix="/rules", tags=["Règles"])
    api_router.include_router(system.router, prefix="/system", tags=["Système"])

# Initialisation des routes
include_routers()
