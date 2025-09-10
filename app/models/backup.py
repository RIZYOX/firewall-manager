"""
Modèle pour les sauvegardes
"""
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from .base import Base, BaseMixin

class BackupStatus(str, PyEnum):
    """Statuts possibles d'une sauvegarde"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RESTORING = "restoring"
    RESTORED = "restored"

class BackupType(str, PyEnum):
    """Types de sauvegarde"""
    FULL = "full"
    DATABASE = "database"
    CONFIG = "config"
    RULES = "rules"

class Backup(Base, BaseMixin):
    """Modèle pour les sauvegardes"""
    __tablename__ = "backups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)  # Taille en octets
    backup_type = Column(Enum(BackupType), default=BackupType.FULL, index=True)
    status = Column(Enum(BackupStatus), default=BackupStatus.PENDING, index=True)
    is_encrypted = Column(Boolean, default=False)
    encryption_key = Column(String(512), nullable=True)
    
    # Métadonnées
    metadata_ = Column("metadata", JSON, nullable=True)  # Utilisation de _ pour éviter le conflit avec la méthode metadata
    
    # Relations
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="backups")
    
    # Pour le suivi
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Backup {self.name} ({self.status})>"
    
    @property
    def is_completed(self):
        """Vérifie si la sauvegarde est terminée avec succès"""
        return self.status == BackupStatus.COMPLETED
    
    @property
    def is_failed(self):
        """Vérifie si la sauvegarde a échoué"""
        return self.status == BackupStatus.FAILED
    
    @property
    def duration(self):
        """Calcule la durée de la sauvegarde en secondes"""
        if not self.started_at:
            return 0
        
        end_time = self.completed_at or datetime.utcnow()
        return (end_time - self.started_at).total_seconds()
    
    def to_dict(self):
        """Convertit l'objet en dictionnaire"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "filename": self.filename,
            "filepath": self.filepath,
            "file_size": self.file_size,
            "file_size_human": self.format_size(),
            "backup_type": self.backup_type.value,
            "status": self.status.value,
            "is_encrypted": self.is_encrypted,
            "metadata": self.metadata_,
            "user_id": self.user_id,
            "user": {
                "id": self.user.id,
                "username": self.user.username,
                "email": self.user.email
            } if self.user else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "error_message": self.error_message
        }
    
    def format_size(self, precision=2):
        """Formate la taille du fichier en unités lisibles"""
        if not self.file_size:
            return "0 B"
            
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.file_size < 1024.0:
                break
            self.file_size /= 1024.0
        
        return f"{self.file_size:.{precision}f} {unit}"
    
    def mark_as_completed(self, db, file_size=None):
        """Marque la sauvegarde comme terminée"""
        self.status = BackupStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if file_size is not None:
            self.file_size = file_size
        db.commit()
    
    def mark_as_failed(self, db, error_message):
        """Marque la sauvegarde comme échouée"""
        self.status = BackupStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = str(error_message)[:1000]  # Limite la taille du message d'erreur
        db.commit()
    
    def mark_as_restoring(self, db):
        """Marque la sauvegarde comme en cours de restauration"""
        self.status = BackupStatus.RESTORING
        db.commit()
    
    def mark_as_restored(self, db):
        """Marque la sauvegarde comme restaurée"""
        self.status = BackupStatus.RESTORED
        db.commit()
    
    @classmethod
    def create_backup(
        cls, 
        db, 
        name: str, 
        backup_type: BackupType = BackupType.FULL,
        description: str = None,
        user_id: int = None,
        metadata: dict = None,
        is_encrypted: bool = False,
        encryption_key: str = None
    ):
        """Crée une nouvelle entrée de sauvegarde"""
        backup = cls(
            name=name,
            description=description,
            backup_type=backup_type,
            status=BackupStatus.IN_PROGRESS,
            user_id=user_id,
            metadata_=metadata,
            is_encrypted=is_encrypted,
            encryption_key=encryption_key,
            started_at=datetime.utcnow()
        )
        db.add(backup)
        db.commit()
        db.refresh(backup)
        return backup
