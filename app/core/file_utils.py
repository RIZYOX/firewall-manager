"""
Utilitaires pour la gestion des fichiers et des sauvegardes
"""
import os
import shutil
import zipfile
import tarfile
import tempfile
import gzip
import hashlib
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Union, BinaryIO, Generator, Callable
from datetime import datetime, timezone

from fastapi import UploadFile, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Backup, User, Log, LogCategory, LogLevel
from app.schemas.backup import BackupCreate, BackupStatus, BackupType

# Configuration du logger
logger = logging.getLogger(__name__)

# Taille maximale des fichiers pour les opérations en mémoire (100 Mo)
MAX_IN_MEMORY_SIZE = 100 * 1024 * 1024

class FileUtils:
    """Classe utilitaire pour les opérations sur les fichiers"""
    
    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        """
        Calcule l'empreinte numérique d'un fichier
        
        Args:
            file_path: Chemin vers le fichier
            algorithm: Algorithme de hachage (sha256, md5, etc.)
            chunk_size: Taille des blocs pour la lecture
            
        Returns:
            L'empreinte numérique du fichier
        """
        hash_algorithm = hashlib.new(algorithm)
        file_path = Path(file_path) if isinstance(file_path, str) else file_path
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_algorithm.update(chunk)
        
        return hash_algorithm.hexdigest()
    
    @staticmethod
    def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Récupère les informations sur un fichier
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            Dictionnaire avec les informations du fichier
        """
        file_path = Path(file_path) if isinstance(file_path, str) else file_path
        stat = file_path.stat()
        
        return {
            'name': file_path.name,
            'path': str(file_path),
            'size': stat.st_size,
            'size_human': FileUtils.format_size(stat.st_size),
            'created_at': datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc),
            'modified_at': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            'accessed_at': datetime.fromtimestamp(stat.st_atime, tz=timezone.utc),
            'is_file': file_path.is_file(),
            'is_dir': file_path.is_dir(),
            'is_symlink': file_path.is_symlink(),
            'mode': oct(stat.st_mode)[-3:],
            'owner': file_path.owner() if hasattr(file_path, 'owner') else None,
            'group': file_path.group() if hasattr(file_path, 'group') else None,
        }
    
    @staticmethod
    def format_size(size_bytes: int, precision: int = 2) -> str:
        """
        Formate une taille en octets dans une unité lisible
        
        Args:
            size_bytes: Taille en octets
            precision: Nombre de décimales à afficher
            
        Returns:
            Chaîne formatée (ex: "1.5 MB")
        """
        if size_bytes == 0:
            return '0 B'
            
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
        unit_index = 0
        size = float(size_bytes)
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.{precision}f} {units[unit_index]}"
    
    @staticmethod
    def ensure_directory_exists(directory: Union[str, Path]) -> Path:
        """
        Crée un répertoire s'il n'existe pas
        
        Args:
            directory: Chemin du répertoire
            
        Returns:
            Objet Path du répertoire
        """
        directory = Path(directory) if isinstance(directory, str) else directory
        directory.mkdir(parents=True, exist_ok=True)
        return directory
    
    @staticmethod
    def clean_filename(filename: str) -> str:
        """
        Nettoie un nom de fichier pour qu'il soit valide sur tous les systèmes
        
        Args:
            filename: Nom de fichier à nettoyer
            
        Returns:
            Nom de fichier nettoyé
        """
        # Caractères non autorisés dans les noms de fichiers
        invalid_chars = '<>:"/\\|?*\0'
        # Remplace les caractères non valides par des tirets bas
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        # Supprime les espaces en début et fin
        filename = filename.strip()
        # Limite la longueur du nom de fichier
        max_length = 255  # Limite commune pour la plupart des systèmes de fichiers
        if len(filename) > max_length:
            name, ext = os.path.splitext(filename)
            name = name[:max_length - len(ext) - 1]
            filename = f"{name}{ext}"
        return filename
    
    @staticmethod
    def save_upload_file(upload_file: UploadFile, destination: Union[str, Path]) -> Path:
        """
        Enregistre un fichier téléchargé sur le disque
        
        Args:
            upload_file: Fichier téléchargé via FastAPI
            destination: Répertoire de destination ou chemin complet
            
        Returns:
            Chemin complet du fichier enregistré
            
        Raises:
            HTTPException: En cas d'erreur lors de l'enregistrement
        """
        try:
            destination = Path(destination)
            
            # Si la destination est un répertoire, on y ajoute le nom du fichier
            if destination.is_dir():
                destination = destination / FileUtils.clean_filename(upload_file.filename)
            
            # Crée le répertoire parent si nécessaire
            destination.parent.mkdir(parents=True, exist_ok=True)
            
            # Écrit le fichier par morceaux pour gérer les gros fichiers
            with open(destination, 'wb') as buffer:
                shutil.copyfileobj(upload_file.file, buffer)
                
            return destination
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du fichier: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Impossible d'enregistrer le fichier: {str(e)}"
            )
        finally:
            upload_file.file.close()
    
    @staticmethod
    def create_backup_archive(
        source_paths: List[Union[str, Path]],
        output_path: Union[str, Path],
        compression: str = 'zip',
        password: Optional[str] = None
    ) -> Path:
        """
        Crée une archive de sauvegarde
        
        Args:
            source_paths: Liste des fichiers/répertoires à inclure
            output_path: Chemin de sortie de l'archive
            compression: Format de compression (zip, tar, tar.gz, tar.bz2)
            password: Mot de passe pour chiffrer l'archive (ZIP uniquement)
            
        Returns:
            Chemin de l'archive créée
            
        Raises:
            ValueError: Si le format de compression n'est pas supporté
        """
        output_path = Path(output_path)
        
        # Vérifie que le format de compression est supporté
        if compression not in ['zip', 'tar', 'tar.gz', 'tar.bz2']:
            raise ValueError(f"Format de compression non supporté: {compression}")
        
        # Crée le répertoire de sortie si nécessaire
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Crée l'archive selon le format demandé
        if compression == 'zip':
            return FileUtils._create_zip_archive(source_paths, output_path, password)
        else:
            return FileUtils._create_tar_archive(source_paths, output_path, compression)
    
    @staticmethod
    def _create_zip_archive(
        source_paths: List[Union[str, Path]],
        output_path: Path,
        password: Optional[str] = None
    ) -> Path:
        """Crée une archive ZIP"""
        import zipfile
        
        with zipfile.ZipFile(
            output_path, 'w',
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9
        ) as zipf:
            # Définit un mot de passe si fourni
            if password:
                zipf.setpassword(password.encode('utf-8'))
            
            # Ajoute chaque source à l'archive
            for source in source_paths:
                source = Path(source)
                if source.is_file():
                    zipf.write(source, source.name)
                elif source.is_dir():
                    for item in source.rglob('*'):
                        if item.is_file():
                            # Préserve la structure des répertoires
                            arcname = str(item.relative_to(source.parent))
                            zipf.write(item, arcname)
        
        return output_path
    
    @staticmethod
    def _create_tar_archive(
        source_paths: List[Union[str, Path]],
        output_path: Path,
        compression: str
    ) -> Path:
        """Crée une archive TAR (avec compression si demandé)"""
        mode = 'w'
        
        # Détermine le mode en fonction de la compression
        if compression == 'tar.gz':
            mode += ':gz'
        elif compression == 'tar.bz2':
            mode += ':bz2'
        
        with tarfile.open(output_path, mode) as tar:
            for source in source_paths:
                source = Path(source)
                if source.is_file() or source.is_dir():
                    tar.add(source, arcname=source.name)
        
        return output_path
    
    @staticmethod
    def extract_archive(
        archive_path: Union[str, Path],
        extract_to: Union[str, Path],
        password: Optional[str] = None
    ) -> Path:
        """
        Extrait une archive
        
        Args:
            archive_path: Chemin vers l'archive
            extract_to: Répertoire de destination
            password: Mot de passe pour les archives protégées
            
        Returns:
            Chemin du répertoire d'extraction
            
        Raises:
            ValueError: Si le format de l'archive n'est pas supporté
        """
        archive_path = Path(archive_path)
        extract_to = Path(extract_to)
        
        # Crée le répertoire d'extraction
        extract_to.mkdir(parents=True, exist_ok=True)
        
        # Détermine le type d'archive
        if zipfile.is_zipfile(archive_path):
            return FileUtils._extract_zip(archive_path, extract_to, password)
        elif tarfile.is_tarfile(archive_path):
            return FileUtils._extract_tar(archive_path, extract_to)
        else:
            raise ValueError("Format d'archive non supporté")
    
    @staticmethod
    def _extract_zip(
        archive_path: Path,
        extract_to: Path,
        password: Optional[str] = None
    ) -> Path:
        """Extrait une archive ZIP"""
        with zipfile.ZipFile(archive_path, 'r') as zipf:
            # Définit le mot de passe si fourni
            if password:
                zipf.setpassword(password.encode('utf-8'))
            
            # Extrait tous les fichiers
            zipf.extractall(extract_to)
        
        return extract_to
    
    @staticmethod
    def _extract_tar(archive_path: Path, extract_to: Path) -> Path:
        """Extrait une archive TAR (avec ou sans compression)"""
        # Détecte la compression
        mode = 'r'
        if str(archive_path).endswith('.gz'):
            mode += ':gz'
        elif str(archive_path).endswith('.bz2'):
            mode += ':bz2'
        
        with tarfile.open(archive_path, mode) as tar:
            tar.extractall(extract_to)
        
        return extract_to
    
    @staticmethod
    def create_backup(
        db: Session,
        backup_data: BackupCreate,
        created_by: Optional[User] = None,
        source_paths: Optional[List[Union[str, Path]]] = None
    ) -> Backup:
        """
        Crée une sauvegarde des fichiers et/ou de la base de données
        
        Args:
            db: Session de base de données
            backup_data: Données de la sauvegarde
            created_by: Utilisateur à l'origine de la sauvegarde
            source_paths: Chemins des fichiers à sauvegarder (si non fourni, utilise les chemins par défaut)
            
        Returns:
            Objet Backup créé
        """
        from app.db.session import SessionLocal
        
        # Définit les chemins par défaut si non fournis
        if source_paths is None:
            source_paths = [
                settings.UPLOAD_FOLDER,
                settings.CONFIG_FILE,
                settings.LOG_FOLDER
            ]
        
        # Crée un nom de fichier unique pour la sauvegarde
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_name = f"backup_{timestamp}"
        if backup_data.backup_type != BackupType.FULL:
            backup_name = f"{backup_name}_{backup_data.backup_type}"
        
        # Définit l'extension en fonction du format de compression
        if backup_data.format == 'zip':
            backup_filename = f"{backup_name}.zip"
        elif backup_data.format == 'tar':
            backup_filename = f"{backup_name}.tar"
        elif backup_data.format == 'tar.gz':
            backup_filename = f"{backup_name}.tar.gz"
        elif backup_data.format == 'tar.bz2':
            backup_filename = f"{backup_name}.tar.bz2"
        else:
            backup_filename = f"{backup_name}.zip"  # Par défaut
        
        # Chemin complet du fichier de sauvegarde
        backup_path = settings.BACKUP_FOLDER / backup_filename
        
        # Crée l'entrée de sauvegarde en base de données
        backup = Backup(
            name=backup_data.name or f"Sauvegarde {backup_data.backup_type.value} {timestamp}",
            description=backup_data.description,
            backup_type=backup_data.backup_type,
            format=backup_data.format,
            file_path=str(backup_path),
            file_size=0,
            status=BackupStatus.PENDING,
            created_by_id=created_by.id if created_by else None,
            metadata=backup_data.metadata or {}
        )
        
        try:
            db.add(backup)
            db.commit()
            db.refresh(backup)
            
            # Met à jour le statut de la sauvegarde
            backup.status = BackupStatus.IN_PROGRESS
            db.commit()
            
            # Crée l'archive de sauvegarde
            FileUtils.create_backup_archive(
                source_paths=source_paths,
                output_path=backup_path,
                compression=backup_data.format,
                password=backup_data.password
            )
            
            # Met à jour les informations de la sauvegarde
            backup.file_size = backup_path.stat().st_size
            backup.status = BackupStatus.COMPLETED
            backup.completed_at = datetime.utcnow()
            backup.metadata.update({
                'file_count': len(list(backup_path.parent.glob('*'))),
                'size_human': FileUtils.format_size(backup.file_size)
            })
            
            db.commit()
            return backup
            
        except Exception as e:
            # En cas d'erreur, met à jour le statut de la sauvegarde
            if 'backup' in locals():
                backup.status = BackupStatus.FAILED
                backup.error_message = str(e)
                db.commit()
            
            logger.error(f"Erreur lors de la création de la sauvegarde: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur lors de la création de la sauvegarde: {str(e)}"
            )
    
    @staticmethod
    def restore_backup(
        db: Session,
        backup: Backup,
        restore_to: Optional[Union[str, Path]] = None,
        password: Optional[str] = None
    ) -> Backup:
        """
        Restaure une sauvegarde
        
        Args:
            db: Session de base de données
            backup: Sauvegarde à restaurer
            restore_to: Répertoire de destination (par défaut: emplacement d'origine)
            password: Mot de passe pour les sauvegardes chiffrées
            
        Returns:
            Objet Backup mis à jour avec le statut de restauration
        """
        try:
            # Vérifie que le fichier de sauvegarde existe
            backup_path = Path(backup.file_path)
            if not backup_path.exists():
                raise FileNotFoundError(f"Le fichier de sauvegarde n'existe pas: {backup_path}")
            
            # Met à jour le statut de la sauvegarde
            backup.status = BackupStatus.RESTORING
            db.commit()
            
            # Définit le répertoire de destination
            if restore_to is None:
                restore_to = settings.BASE_DIR
            else:
                restore_to = Path(restore_to)
                restore_to.mkdir(parents=True, exist_ok=True)
            
            # Extrait l'archive
            FileUtils.extract_archive(
                archive_path=backup_path,
                extract_to=restore_to,
                password=password or backup.metadata.get('password')
            )
            
            # Met à jour le statut de la sauvegarde
            backup.status = BackupStatus.RESTORED
            backup.restored_at = datetime.utcnow()
            backup.metadata['restored_to'] = str(restore_to)
            db.commit()
            
            return backup
            
        except Exception as e:
            # En cas d'erreur, met à jour le statut de la sauvegarde
            backup.status = BackupStatus.FAILED
            backup.error_message = str(e)
            db.commit()
            
            logger.error(f"Erreur lors de la restauration de la sauvegarde: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur lors de la restauration de la sauvegarde: {str(e)}"
            )
    
    @staticmethod
    def cleanup_old_backups(db: Session, max_backups: int = 10) -> int:
        """
        Supprime les anciennes sauvegardes pour ne garder que les N plus récentes
        
        Args:
            db: Session de base de données
            max_backups: Nombre maximum de sauvegardes à conserver
            
        Returns:
            Nombre de sauvegardes supprimées
        """
        # Récupère toutes les sauvegardes triées par date de création (les plus anciennes en premier)
        backups = db.query(Backup)\
            .filter(Backup.status.in_([BackupStatus.COMPLETED, BackupStatus.RESTORED]))\
            .order_by(Backup.created_at.asc())\
            .all()
        
        # Calcule le nombre de sauvegardes à supprimer
        to_delete = len(backups) - max_backups
        
        if to_delete <= 0:
            return 0
        
        deleted_count = 0
        
        # Supprime les sauvegardes les plus anciennes
        for backup in backups[:to_delete]:
            try:
                # Supprime le fichier de sauvegarde
                backup_path = Path(backup.file_path)
                if backup_path.exists():
                    backup_path.unlink()
                
                # Supprime l'entrée en base de données
                db.delete(backup)
                deleted_count += 1
                
            except Exception as e:
                logger.error(f"Erreur lors de la suppression de la sauvegarde {backup.id}: {str(e)}")
        
        # Valide les modifications en base de données
        if deleted_count > 0:
            db.commit()
        
        return deleted_count
    
    @staticmethod
    def stream_file(file_path: Union[str, Path], chunk_size: int = 8192) -> Generator[bytes, None, None]:
        """
        Génère un flux de données à partir d'un fichier par morceaux
        
        Args:
            file_path: Chemin vers le fichier à lire
            chunk_size: Taille des morceaux en octets
            
        Yields:
            Morceaux de données binaires
        """
        file_path = Path(file_path)
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    
    @staticmethod
    def get_mime_type(file_path: Union[str, Path]) -> str:
        """
        Détermine le type MIME d'un fichier
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            Type MIME du fichier (par défaut: application/octet-stream)
        """
        import mimetypes
        file_path = Path(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or 'application/octet-stream'
