"""
Firewall Simple - Point d'entrée principal
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import os

app = FastAPI(title="Firewall Simple")

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modèles
class Rule(BaseModel):
    name: str
    action: str  # 'allow' ou 'deny'
    protocol: str
    port: int
    source: str = "any"
    description: str = ""

# Base de données
def get_db():
    db = sqlite3.connect('firewall.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    if not os.path.exists('firewall.db'):
        db = get_db()
        cursor = db.cursor()
        
        # Création de la table des règles
        cursor.execute('''
        CREATE TABLE rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            action TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            source TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Ajout de règles par défaut
        default_rules = [
            ('Allow SSH', 'allow', 'tcp', 22, 'any', 'SSH access'),
            ('Allow HTTP', 'allow', 'tcp', 80, 'any', 'HTTP access'),
            ('Allow HTTPS', 'allow', 'tcp', 443, 'any', 'HTTPS access'),
            ('Block All', 'deny', 'any', 0, 'any', 'Default deny rule')
        ]
        
        cursor.executemany('''
        INSERT INTO rules (name, action, protocol, port, source, description)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', default_rules)
        
        db.commit()
        db.close()

# Routes
@app.get("/")
def read_root():
    return {"message": "Bienvenue sur Firewall Simple"}

@app.get("/rules")
def list_rules():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM rules ORDER BY created_at DESC')
    rules = [dict(row) for row in cursor.fetchall()]
    db.close()
    return {"rules": rules}

@app.post("/rules")
def add_rule(rule: Rule):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
    INSERT INTO rules (name, action, protocol, port, source, description)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        rule.name,
        rule.action,
        rule.protocol,
        rule.port,
        rule.source,
        rule.description
    ))
    
    db.commit()
    db.close()
    
    return {"status": "success", "message": "Règle ajoutée"}

@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: int):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
    db.commit()
    deleted = cursor.rowcount > 0
    db.close()
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Règle non trouvée")
    
    return {"status": "success", "message": "Règle supprimée"}

# Initialisation
if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
