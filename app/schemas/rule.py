"""
Schémas pour les règles de pare-feu
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Union
from datetime import datetime
from enum import Enum

class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"

class RuleDirection(str, Enum):
    IN = "in"
    OUT = "out"
    BOTH = "both"

class RuleBase(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    action: RuleAction
    direction: RuleDirection = RuleDirection.BOTH
    protocol: str = Field("tcp", regex="^(tcp|udp|icmp|any)$")
    port: str = Field(..., description="Port ou plage de ports (ex: 80, 1000-2000, 80,443,8080)")
    source: str = Field("any", description="Adresse IP ou réseau source")
    destination: str = Field("any", description="Adresse IP ou réseau de destination")
    is_active: bool = True

    @validator('port')
    def validate_port(cls, v):
        # Valide les formats de port : 80, 1000-2000, 80,443,8080
        import re
        port_pattern = r'^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$'
        if not re.match(port_pattern, v):
            raise ValueError("Format de port invalide. Exemples valides : 80, 1000-2000, 80,443,8080")
        return v

class RuleCreate(RuleBase):
    pass

class RuleUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    action: Optional[RuleAction] = None
    direction: Optional[RuleDirection] = None
    protocol: Optional[str] = Field(None, regex="^(tcp|udp|icmp|any)$")
    port: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    is_active: Optional[bool] = None

class RuleInDBBase(RuleBase):
    id: int
    is_system: bool = False
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

class Rule(RuleInDBBase):
    pass

class RuleApply(BaseModel):
    rule_ids: List[int] = Field(..., description="Liste des IDs de règles à appliquer")
    save_to_boot: bool = Field(True, description="Sauvegarder les règles au démarrage")

class RuleTest(BaseModel):
    protocol: str = Field(..., regex="^(tcp|udp|icmp)$")
    port: int = Field(..., ge=1, le=65535)
    source: str = Field("any", description="Adresse IP source pour le test")
    destination: str = Field("any", description="Adresse IP de destination pour le test")
