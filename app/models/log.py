"""
Modèle pour les journaux d'activité
"""
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .base import Base, BaseMixin

class LogLevel(str, PyEnum):
    """Niveaux de gravité des logs"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogCategory(str, PyEnum):
    """Catégories de logs"""
    AUTH = "authentication"
    RULE = "firewall_rule"
    SYSTEM = "system"
    NETWORK = "network"
    SECURITY = "security"
    BACKUP = "backup"
    UPDATE = "update"
    OTHER = "other"

class Log(Base, BaseMixin):
    """Modèle pour les entrées de journal"""
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    level = Column(Enum(LogLevel), default=LogLevel.INFO, index=True)
    category = Column(Enum(LogCategory), default=LogCategory.OTHER, index=True)
    source = Column(String(100), nullable=True, index=True)
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    
    # Relations
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="logs")
    
    # Pour le suivi des actions
    action = Column(String(100), nullable=True, index=True)
    object_type = Column(String(100), nullable=True, index=True)
    object_id = Column(String(100), nullable=True, index=True)
    
    # Adresse IP de l'utilisateur
    ip_address = Column(String(45), nullable=True, index=True)
    
    # User-Agent
    user_agent = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Log {self.timestamp} [{self.level.upper()}] {self.message[:50]}...>"
    
    def to_dict(self):
        """Convertit l'objet en dictionnaire"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level.value,
            "category": self.category.value,
            "source": self.source,
            "message": self.message,
            "details": self.details,
            "user_id": self.user_id,
            "user": {
                "id": self.user.id,
                "username": self.user.username,
                "email": self.user.email
            } if self.user else None,
            "action": self.action,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def create(
        cls, 
        db, 
        message: str, 
        level: LogLevel = LogLevel.INFO,
        category: LogCategory = LogCategory.OTHER,
        source: str = None,
        details: dict = None,
        user_id: int = None,
        action: str = None,
        object_type: str = None,
        object_id: str = None,
        ip_address: str = None,
        user_agent: str = None
    ):
        """Crée une nouvelle entrée de journal"""
        log = cls(
            message=message,
            level=level,
            category=category,
            source=source,
            details=details,
            user_id=user_id,
            action=action,
            object_type=object_type,
            object_id=object_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log
