"""
Endpoints pour la gestion des règles de pare-feu
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.security import get_current_user
from app.models import Rule as DBRule, User
from app.schemas.rule import Rule, RuleCreate, RuleUpdate, RuleApply, RuleTest
from app.db.session import get_db

router = APIRouter()

@router.get("/", response_model=List[Rule])
async def list_rules(
    skip: int = 0,
    limit: int = 100,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Liste toutes les règles de pare-feu"""
    query = db.query(DBRule)
    
    if is_active is not None:
        query = query.filter(DBRule.is_active == is_active)
        
    rules = query.offset(skip).limit(limit).all()
    return rules

@router.post("/", response_model=Rule, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: RuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Crée une nouvelle règle de pare-feu"""
    db_rule = DBRule(**rule.dict(), owner_id=current_user.id)
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.get("/{rule_id}", response_model=Rule)
async def get_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Récupère une règle par son ID"""
    db_rule = db.query(DBRule).filter(DBRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Règle non trouvée")
    return db_rule

@router.put("/{rule_id}", response_model=Rule)
async def update_rule(
    rule_id: int,
    rule: RuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Met à jour une règle existante"""
    db_rule = db.query(DBRule).filter(DBRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Règle non trouvée")
        
    # Empêche la modification des règles système sauf pour les superutilisateurs
    if db_rule.is_system and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous n'êtes pas autorisé à modifier cette règle système"
        )
    
    update_data = rule.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_rule, field, value)
        
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Supprime une règle"""
    db_rule = db.query(DBRule).filter(DBRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Règle non trouvée")
        
    # Empêche la suppression des règles système
    if db_rule.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Impossible de supprimer une règle système"
        )
        
    db.delete(db_rule)
    db.commit()
    return None

@router.post("/apply", status_code=status.HTTP_200_OK)
async def apply_rules(
    data: RuleApply,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Applique les règles sélectionnées au pare-feu système"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action non autorisée"
        )
    
    # Récupère les règles actives
    rules = db.query(DBRule).filter(
        DBRule.id.in_(data.rule_ids),
        DBRule.is_active == True
    ).all()
    
    # Ici, vous devriez implémenter la logique pour appliquer les règles
    # au pare-feu système (UFW, iptables, etc.)
    
    # Exemple de logique à implémenter :
    # for rule in rules:
    #     apply_rule_to_firewall(rule)
    # 
    # if data.save_to_boot:
    #     save_firewall_rules()
    
    return {"status": "success", "message": f"{len(rules)} règles appliquées avec succès"}

@router.post("/test", status_code=status.HTTP_200_OK)
async def test_rule(
    test: RuleTest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Teste si une règle serait appliquée"""
    # Ici, vous devriez implémenter la logique pour tester une règle
    # sans l'appliquer réellement
    
    # Exemple de logique à implémenter :
    # result = test_firewall_rule(
    #     protocol=test.protocol,
    #     port=test.port,
    #     source=test.source,
    #     destination=test.destination
    # )
    
    # Pour l'instant, on simule une réponse
    return {
        "would_allow": True,
        "matching_rules": ["allow tcp port 80 from any to any"],
        "applied_rule": "allow tcp port 80 from any to any"
    }
