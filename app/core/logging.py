"""
Configuration du logging
"""
import logging
import logging.config
import os
import sys
from pathlib import Path
from typing import Dict, Any
import json

from app.core.config import settings

def setup_logging():
    """Configure le système de logging"""
    # Création du dossier de logs s'il n'existe pas
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configuration du logging
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "json": {
                "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": """
                    asctime: %(asctime)s
                    name: %(name)s
                    levelname: %(levelname)s
                    message: %(message)s
                    pathname: %(pathname)s
                    funcName: %(funcName)s
                    lineno: %(lineno)d
                """
            }
        },
        "handlers": {
            "console": {
                "level": "INFO",
                "formatter": "standard",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            },
            "file": {
                "level": "DEBUG",
                "formatter": "json",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": log_dir / "firewall.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf8"
            },
            "error_file": {
                "level": "ERROR",
                "formatter": "json",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": log_dir / "error.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf8"
            }
        },
        "loggers": {
            "": {  # root logger
                "handlers": ["console", "file", "error_file"],
                "level": "DEBUG" if settings.DEBUG else "INFO",
                "propagate": False
            },
            "app": {
                "handlers": ["console", "file", "error_file"],
                "level": "DEBUG" if settings.DEBUG else "INFO",
                "propagate": False
            },
            "uvicorn": {
                "handlers": ["console", "file"],
                "level": "INFO",
                "propagate": False
            },
            "uvicorn.error": {
                "handlers": ["console", "error_file"],
                "level": "INFO",
                "propagate": False
            },
            "sqlalchemy": {
                "handlers": ["console"],
                "level": "WARNING",
                "propagate": False
            }
        }
    }
    
    # Application de la configuration
    logging.config.dictConfig(log_config)
    
    # Désactive les logs de requêtes de certaines bibliothèques en production
    if not settings.DEBUG:
        logging.getLogger("uvicorn.access").disabled = True
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    # Capture les exceptions non gérées
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logger = logging.getLogger("app")
        logger.critical(
            "Exception non gérée",
            exc_info=(exc_type, exc_value, exc_traceback)
        )
    
    sys.excepthook = handle_exception
