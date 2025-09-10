"""
Modèle utilisateur
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from .base import Base, BaseMixin

class User(Base, BaseMixin):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=True)
    
    # Relations
    rules = relationship("Rule", back_populates="owner")
    
    def __repr__(self):
        return f"<User {self.username}>"
    
    @property
    def is_authenticated(self):
        return self.is_active
    
    def get_id(self):
        return str(self.id)
