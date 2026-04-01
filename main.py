import os
from fastapi import FastAPI, HTTPException, Depends, Header
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from typing import Dict, Any
import bcrypt
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import certifi

# 1. Carica le variabili dal file .env (se presente, altrimenti le prenderà da Render)
load_dotenv()

app = FastAPI(title="QueryRouter Cloud Sync")

# --- CONFIGURAZIONE E SICUREZZA ---
MONGO_URL = os.getenv("MONGO_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Controllo di sicurezza: ferma il server se mancano le chiavi
if not MONGO_URL or not SECRET_KEY:
    raise ValueError("⚠️ ATTENZIONE: Le variabili d'ambiente MONGO_URL o SECRET_KEY non sono impostate!")

# Connessione a MongoDB
client = AsyncIOMotorClient(MONGO_URL, tlsCAFile=certifi.where())
db = client.queryrouter_db  
users_col = db.users        
configs_col = db.configs    

# --- MODELLI DATI ---
class UserAuth(BaseModel):
    username: str
    password: str

class ShortcutSync(BaseModel):
    config_data: Dict[str, Any]

# --- FUNZIONI DI SUPPORTO (JWT) ---
def create_token(username: str):
    scadenza = datetime.utcnow() + timedelta(days=30)
    dati = {"user": username, "exp": scadenza}
    return jwt.encode(dati, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Devi prima fare il login")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("user")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token non valido o scaduto")

# --- ENDPOINTS (Le API del server) ---

@app.post("/register")
async def register(user: UserAuth):
    if await users_col.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username già in uso")
    
    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    
    await users_col.insert_one({
        "username": user.username, 
        "password": hashed_pw
    })
    return {"status": "success", "message": "Account creato con successo!"}

@app.post("/login")
async def login(user: UserAuth):
    db_user = await users_col.find_one({"username": user.username})
    
    if db_user and bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"]):
        token = create_token(user.username)
        return {"access_token": token}
        
    raise HTTPException(status_code=401, detail="Credenziali errate")

@app.post("/sync")
async def sync_dati(data: ShortcutSync, username: str = Depends(get_current_user)):
    await configs_col.update_one(
        {"username": username},
        {"$set": {"data": data.config_data}},
        upsert=True 
    )
    return {"status": "success", "message": "Sincronizzato sul Cloud!"}

@app.get("/fetch")
async def fetch_dati(username: str = Depends(get_current_user)):
    config = await configs_col.find_one({"username": username})
    if not config:
        return {} 
    return config["data"]