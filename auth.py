import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from firebase_config import db
from passlib.context import CryptContext
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")  # kalau belum ada .env
ALGORITHM = "HS256"

# 📦 Skema input user
class UserSignup(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# 🔐 Hash password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT Token Generator
def create_access_token(user_id: str, expires_minutes: int = 60):
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {"sub": user_id, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# REGISTER endpoint
@router.post("/register")
def register_user(user: UserSignup):
    # Cek kalau user sudah ada
    existing_user = db.collection("users").where("email", "==", user.email).get()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    hashed = hash_password(user.password)

    db.collection("users").document(user_id).set({
        "user_id": user_id,
        "email": user.email,
        "username": user.username,
        "hashed_password": hashed,
        "created_at": datetime.utcnow().isoformat()
    })

    token = create_access_token(user_id)
    return {"message": "User registered", "token": token}

# LOGIN endpoint
@router.post("/login")
def login_user(user: UserLogin):
    user_docs = db.collection("users").where("email", "==", user.email).get()

    if not user_docs:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_data = user_docs[0].to_dict()

    if not verify_password(user.password, user_data["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user_data["user_id"])
    return {"message": "Login successful", "token": token}
