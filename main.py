import os
import ssl
from fastapi import FastAPI, HTTPException, Depends, Header
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from typing import Dict, Any
import bcrypt
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Carica le variabili dal file .env
load_dotenv()

app = FastAPI(title="QueryRouter Cloud Sync")

# --- 1. CONFIGURAZIONE E SICUREZZA ---
MONGO_URL = os.getenv("MONGO_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
# Se non trova la variabile ENVIRONMENT, assume che sia su Render ("production")
ENVIRONMENT = os.getenv("ENVIRONMENT", "production") 
ALGORITHM = "HS256"

# Controllo di sicurezza
if not MONGO_URL or not SECRET_KEY:
    raise ValueError("⚠️ ATTENZIONE: Le variabili d'ambiente MONGO_URL o SECRET_KEY non sono impostate!")

# --- 2. CONNESSIONE INTELLIGENTE A MONGODB ---
if ENVIRONMENT == "local":
    print("⚠️ Avvio in modalità LOCALE: Bypass SSL di Windows attivo.")
    # Patch per Windows: ignora i certificati locali
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client = AsyncIOMotorClient(MONGO_URL, tls=True, tlsAllowInvalidCertificates=True)
else:
    print("✅ Avvio in modalità PRODUZIONE: Connessione sicura attiva.")
    # Connessione standard (Render)
    client = AsyncIOMotorClient(MONGO_URL)

db = client.queryrouter_db  
users_col = db.users        
configs_col = db.configs    

# --- 3. MODELLI DATI ---
class UserAuth(BaseModel):
    username: str
    password: str

class ShortcutSync(BaseModel):
    config_data: Dict[str, Any]

# --- 4. FUNZIONI DI SUPPORTO (JWT) ---
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

# --- 5. ENDPOINTS (Le API del server) ---

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