"""
Modèle pour les règles de pare-feu
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from .base import Base, BaseMixin, RuleAction, RuleDirection

class Rule(Base, BaseMixin):
    __tablename__ = "rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    
    # Détails de la règle
    action = Column(Enum(RuleAction), nullable=False)
    direction = Column(Enum(RuleDirection), default=RuleDirection.BOTH)
    protocol = Column(String(10), default="tcp")
    port = Column(String(50), nullable=False)  # Peut être une plage ou une liste
    source = Column(String(50), default="any")
    destination = Column(String(50), default="any")
    
    # Options
    is_active = Column(Boolean, default=True)
    is_system = Column(Boolean, default=False)  # Pour les règles système
    
    # Relations
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", back_populates="rules")
    
    def __repr__(self):
        return f"<Rule {self.name} ({self.action} {self.port}/{self.protocol})>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "action": self.action.value,
            "direction": self.direction.value,
            "protocol": self.protocol,
            "port": self.port,
            "source": self.source,
            "destination": self.destination,
            "is_active": self.is_active,
            "is_system": self.is_system,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
