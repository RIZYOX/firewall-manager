"""
Modèles de base de données
"""
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Enum, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session
from datetime import datetime
import enum
import os

# Configuration de la base de données
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./firewall.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})

# Session de base de données
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Fournit une session de base de données"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Modèle de base
class BaseMixin:
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Enums
class RuleAction(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"

class RuleDirection(str, enum.Enum):
    IN = "in"
    OUT = "out"
    BOTH = "both"

# Modèles
def init_db():
    """Initialise la base de données"""
    Base.metadata.create_all(bind=engine)
    
    # Créer un utilisateur admin par défaut si nécessaire
    db = SessionLocal()
    try:
        from ..schemas.user import UserCreate
        from .user import User
        from ..core.security import get_password_hash
        
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                email="admin@example.com",
                hashed_password=get_password_hash("admin"),
                is_superuser=True,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
    except Exception as e:
        print(f"Erreur lors de l'initialisation de la base de données: {e}")
        db.rollback()
    finally:
        db.close()
