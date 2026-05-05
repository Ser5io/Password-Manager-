from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from backend.db.manager import DatabaseManager
from backend.core.crypto import CryptoManager
from backend.services.auth import AuthService
from backend.services.vault import VaultService

app = FastAPI(title="Secure Password Manager API")

# Initialize components
db = DatabaseManager()
crypto = CryptoManager()
auth_service = AuthService(db, crypto)
vault_service = VaultService(db, crypto)

# Models
class UserRegister(BaseModel):
    email: EmailStr
    master_password: str

class UserLogin(BaseModel):
    email: EmailStr
    master_password: str

class VaultItem(BaseModel):
    name: str
    username: str
    password: str
    url: str

# Endpoints
@app.post("/auth/register")
def register(user: UserRegister):
    try:
        auth_service.register(user.email, user.master_password)
        return {"message": "User registered successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/login")
def login(user: UserLogin):
    authenticated_user = auth_service.login(user.email, user.master_password)
    if not authenticated_user:
        raise HTTPException(status_code=401, detail="Invalid email or master password")
    return authenticated_user

@app.get("/vault")
def get_vault(user_id: int, master_password: str):
    # In a real app, use JWT and don't pass master_password in query
    # This is a simplified version for architectural demonstration
    return vault_service.get_items(user_id, master_password)

@app.post("/vault/items")
def add_vault_item(user_id: int, master_password: str, item: VaultItem):
    vault_service.add_item(user_id, master_password, item.dict())
    return {"message": "Item added successfully"}

@app.delete("/vault/items/{item_id}")
def delete_vault_item(user_id: int, item_id: int):
    vault_service.delete_item(user_id, item_id)
    return {"message": "Item deleted"}

@app.get("/vault/export")
def export_vault(user_id: int):
    return {"encrypted_vault": vault_service.export_vault(user_id)}

@app.post("/vault/import")
def import_vault(user_id: int, data: dict):
    vault_service.import_vault(user_id, data["encrypted_vault"])
    return {"message": "Vault imported"}

@app.get("/utils/generate-password")
def generate_password(length: int = 16):
    try:
        return {"password": crypto.generate_strong_password(length)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
