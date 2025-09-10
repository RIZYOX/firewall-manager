"""
Configuration des clés API pour les services d'IA
Ce fichier est chargé depuis .env pour plus de sécurité
"""
from pydantic import BaseSettings, Field, validator
from typing import Optional

class AIConfig(BaseSettings):
    # Configuration OpenAI
    OPENAI_API_KEY: Optional[str] = Field(None, env='OPENAI_API_KEY')
    OPENAI_ORGANIZATION: Optional[str] = Field(None, env='OPENAI_ORGANIZATION')
    
    # Configuration Google Cloud
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = Field(None, env='GOOGLE_APPLICATION_CREDENTIALS')
    
    # Configuration Azure AI
    AZURE_OPENAI_API_KEY: Optional[str] = Field(None, env='AZURE_OPENAI_API_KEY')
    AZURE_OPENAI_ENDPOINT: Optional[str] = Field(None, env='AZURE_OPENAI_ENDPOINT')
    
    # Autres fournisseurs d'IA
    HUGGINGFACEHUB_API_TOKEN: Optional[str] = Field(None, env='HUGGINGFACEHUB_API_TOKEN')
    ANTHROPIC_API_KEY: Optional[str] = Field(None, env='ANTHROPIC_API_KEY')
    
    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        case_sensitive = True

# Instance de configuration
aiconfig = AIConfig()

def get_ai_config() -> AIConfig:
    """Retourne la configuration des services d'IA"""
    return aiconfig
