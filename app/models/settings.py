"""
Modèle pour les paramètres de l'application
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON
from sqlalchemy.orm import validates
from .base import Base, BaseMixin

class Setting(Base, BaseMixin):
    """Modèle pour les paramètres de l'application"""
    __tablename__ = "settings"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    value_type = Column(String(20), default="string")  # string, integer, float, boolean, json
    is_public = Column(Boolean, default=True, index=True)
    is_required = Column(Boolean, default=False)
    category = Column(String(50), default="general", index=True)
    description = Column(Text, nullable=True)
    options = Column(JSON, nullable=True)  # Pour les champs avec des options prédéfinies
    
    # Validation
    min_value = Column(String(50), nullable=True)
    max_value = Column(String(50), nullable=True)
    regex = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<Setting {self.key}={self.value}>"
    
    @validates('key')
    def validate_key(self, key, value):
        """Valide que la clé est en minuscules et utilise des underscores"""
        if not value.replace('_', '').isalnum():
            raise ValueError("La clé ne doit contenir que des lettres, des chiffres et des underscores")
        return value.lower()
    
    def get_value(self):
        """Retourne la valeur avec le bon type"""
        if self.value is None:
            return None
            
        if self.value_type == "integer":
            return int(self.value)
        elif self.value_type == "float":
            return float(self.value)
        elif self.value_type == "boolean":
            return self.value.lower() in ('true', '1', 't', 'y', 'yes')
        elif self.value_type == "json":
            import json
            return json.loads(self.value)
        else:  # string
            return self.value
    
    def set_value(self, value):
        """Définit la valeur avec conversion en chaîne"""
        if value is None:
            self.value = None
            return
            
        if self.value_type == "json":
            import json
            self.value = json.dumps(value)
        else:
            self.value = str(value)
    
    def to_dict(self, include_value=True):
        """Convertit l'objet en dictionnaire"""
        result = {
            "id": self.id,
            "key": self.key,
            "value_type": self.value_type,
            "is_public": self.is_public,
            "is_required": self.is_required,
            "category": self.category,
            "description": self.description,
            "options": self.options,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "regex": self.regex,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_value:
            result["value"] = self.get_value()
            
        return result
    
    @classmethod
    def get_setting(cls, db, key, default=None):
        """Récupère un paramètre par sa clé"""
        setting = db.query(cls).filter(cls.key == key).first()
        if setting:
            return setting.get_value()
        return default
    
    @classmethod
    def set_setting(cls, db, key, value, value_type="string", **kwargs):
        """Définit un paramètre"""
        setting = db.query(cls).filter(cls.key == key).first()
        
        if not setting:
            setting = cls(key=key, value_type=value_type, **kwargs)
            db.add(setting)
        
        setting.set_value(value)
        
        # Met à jour les autres champs si fournis
        for field, field_value in kwargs.items():
            if hasattr(setting, field):
                setattr(setting, field, field_value)
        
        db.commit()
        db.refresh(setting)
        return setting
    
    @classmethod
    def get_all_settings(cls, db, include_private=False):
        """Récupère tous les paramètres"""
        query = db.query(cls)
        
        if not include_private:
            query = query.filter(cls.is_public == True)
            
        settings = query.all()
        return {setting.key: setting.get_value() for setting in settings}
    
    @classmethod
    def get_settings_by_category(cls, db, category, include_private=False):
        """Récupère les paramètres par catégorie"""
        query = db.query(cls).filter(cls.category == category)
        
        if not include_private:
            query = query.filter(cls.is_public == True)
            
        settings = query.all()
        return {setting.key: setting.get_value() for setting in settings}
    
    @classmethod
    def initialize_default_settings(cls, db):
        """Initialise les paramètres par défaut"""
        default_settings = [
            # Paramètres généraux
            {
                "key": "app_name",
                "value": "Firewall Manager",
                "value_type": "string",
                "category": "general",
                "description": "Nom de l'application",
                "is_public": True,
                "is_required": True
            },
            {
                "key": "app_description",
                "value": "Gestionnaire de pare-feu avec interface web",
                "value_type": "string",
                "category": "general",
                "description": "Description de l'application",
                "is_public": True
            },
            
            # Paramètres du pare-feu
            {
                "key": "firewall_service",
                "value": "ufw",
                "value_type": "string",
                "category": "firewall",
                "description": "Service de pare-feu à utiliser (ufw, iptables, firewalld)",
                "is_public": True,
                "is_required": True,
                "options": ["ufw", "iptables", "firewalld"]
            },
            {
                "key": "default_policy",
                "value": "deny",
                "value_type": "string",
                "category": "firewall",
                "description": "Politique par défaut pour les connexions entrantes",
                "is_public": True,
                "options": ["allow", "deny", "reject"]
            },
            
            # Paramètres de sécurité
            {
                "key": "login_attempts",
                "value": "5",
                "value_type": "integer",
                "category": "security",
                "description": "Nombre maximum de tentatives de connexion échouées avant blocage",
                "is_public": True,
                "min_value": "1",
                "max_value": "20"
            },
            {
                "key": "session_timeout",
                "value": "30",
                "value_type": "integer",
                "category": "security",
                "description": "Délai d'expiration de la session en minutes",
                "is_public": True,
                "min_value": "1",
                "max_value": "1440"  # 24 heures
            },
            
            # Paramètres de notification
            {
                "key": "email_notifications",
                "value": "false",
                "value_type": "boolean",
                "category": "notifications",
                "description": "Activer les notifications par email",
                "is_public": True
            },
            {
                "key": "admin_email",
                "value": "admin@example.com",
                "value_type": "string",
                "category": "notifications",
                "description": "Email de l'administrateur pour les notifications",
                "is_public": False,
                "regex": r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
            }
        ]
        
        for setting_data in default_settings:
            if not db.query(cls).filter(cls.key == setting_data["key"]).first():
                setting = cls(**setting_data)
                db.add(setting)
        
        db.commit()
        
        return len(default_settings)
