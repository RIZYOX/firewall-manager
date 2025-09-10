"""
Vues de l'application web
"""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

# Configuration des templates
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
):
    """Page d'accueil du tableau de bord"""
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "title": "Tableau de bord",
            "page": "dashboard"
        }
    )

@router.get("/rules", response_class=HTMLResponse)
async def rules_page(
    request: Request,
):
    """Page de gestion des règles"""
    return templates.TemplateResponse(
        "rules.html",
        {
            "request": request,
            "title": "Gestion des règles",
            "page": "rules"
        }
    )

@router.get("/logs", response_class=HTMLResponse)
async def logs_page(
    request: Request,
):
    """Page des journaux"""
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "title": "Journaux système",
            "page": "logs"
        }
    )

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
):
    """Page des paramètres"""
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "title": "Paramètres",
            "page": "settings"
        }
    )

@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
):
    """Page de connexion"""
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "title": "Connexion",
            "page": "login"
        }
    )
