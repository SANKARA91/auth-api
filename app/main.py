import os
import time

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

SECRET = os.environ["JWT_SECRET"]  # l'appli refuse de démarrer sans secret
TTL = 900  # durée de vie du jeton : 15 minutes

app = FastAPI(title="auth-api")
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