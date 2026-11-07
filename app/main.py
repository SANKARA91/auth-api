import os
import time

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
SECRET = os.environ["JWT_SECRET"]  # l'appli refuse de démarrer sans secret
TTL = 900  # durée de vie du jeton : 15 minutes

app = FastAPI(title="auth-api v2")
bearer = HTTPBearer()

users = {}  # stockage en mémoire, perdu à chaque redémarrage (démo)


class Credentials(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
def register(c: Credentials):
    if c.username in users:
        raise HTTPException(status_code=409, detail="Utilisateur existant")
    if len(c.password) < 8:
        raise HTTPException(status_code=400, detail="Mot de passe trop court")
    users[c.username] = bcrypt.hashpw(c.password.encode(), bcrypt.gensalt())
    return {"username": c.username}


@app.post("/login")
def login(c: Credentials):
    h = users.get(c.username)
    if not h or not bcrypt.checkpw(c.password.encode(), h):
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    now = int(time.time())
    token = jwt.encode(
        {"sub": c.username, "iat": now, "exp": now + TTL},
        SECRET,
        algorithm="HS256",
    )
    return {"access_token": token, "token_type": "bearer"}


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        payload = jwt.decode(cred.credentials, SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Jeton invalide ou expiré")
    return payload["sub"]


@app.get("/me")
def me(user: str = Depends(current_user)):
    return {"username": user}
    
PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Connexion</title>
<style>
body{font-family:sans-serif;max-width:340px;margin:60px auto}
input,button{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}
#msg{margin-top:12px;font-weight:bold}
</style></head><body>
<h2>Connexion</h2>
<input id="u" placeholder="Nom d'utilisateur">
<input id="p" type="password" placeholder="Mot de passe">
<button onclick="send('/login')">Se connecter</button>
<button onclick="send('/register')">Créer un compte</button>
<div id="msg"></div>
<script>
let token = null;
async function send(path){
  const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u.value,password:p.value})});
  const d = await r.json();
  if(path==='/login' && r.ok){
    token = d.access_token;
    const me = await fetch('/me',{headers:{Authorization:'Bearer '+token}});
    msg.textContent = 'Connecté : ' + (await me.json()).username;
  } else {
    msg.textContent = r.ok ? 'Compte créé, connectez-vous' : (d.detail || 'Erreur');
  }
}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return PAGE