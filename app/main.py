from fastapi import FastAPI, HTTPException, status, Response, Request, Header, Form, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from typing import Optional, List
from datetime import datetime
import uuid
import time
import re

app = FastAPI(title="Контрольная работа №2")


SECRET_KEY = "change-this-in-production-please"
SESSION_DURATION = 300  
RENEWAL_THRESHOLD = 180  
serializer = URLSafeTimedSerializer(SECRET_KEY)


class UserCreate(BaseModel):
    name: str = Field(..., min_length=1)
    email: EmailStr
    age: Optional[int] = Field(default=None, ge=1)
    is_subscribed: Optional[bool] = False

    @field_validator('name')
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError('Имя не может быть пустым')
        return v.strip()



class CommonHeaders(BaseModel):
    user_agent: str = Field(..., alias="User-Agent")
    accept_language: str = Field(..., alias="Accept-Language")
    
    @field_validator('accept_language')
    @classmethod
    def validate_accept_language(cls, v: str) -> str:
        pattern = r'^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})?(,[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})?;q=0\.\d{1,2})*$'
        if not re.match(pattern, v):
            raise ValueError('Invalid Accept-Language format')
        return v
    
    class Config:
        populate_by_name = True


sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99},
]


VALID_CREDENTIALS = {
    "user123": {"password": "password123", "user_id": str(uuid.uuid4())}
}

def create_session_token(user_id: str, timestamp: int) -> str:
    payload = f"{user_id}.{timestamp}"
    signature = serializer.dumps(payload)
    return f"{payload}.{signature}"

def verify_session_token(token: str) -> Optional[tuple]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        user_id = parts[0]
        timestamp_str = parts[1]
        signature = ".".join(parts[2:])
        payload = f"{user_id}.{timestamp_str}"
        decoded_payload = serializer.loads(signature, max_age=SESSION_DURATION + 60)
        if decoded_payload != payload:
            return None
        timestamp = int(timestamp_str)
        return user_id, timestamp
    except (BadSignature, SignatureExpired, ValueError, IndexError):
        return None


#  3.1 
@app.post("/create_user", status_code=status.HTTP_200_OK)
def create_user(user: UserCreate):
    return {
        "name": user.name,
        "email": user.email,
        "age": user.age,
        "is_subscribed": user.is_subscribed
    }


# 3.2 
@app.get("/product/{product_id}")
def get_product(product_id: int):
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")

@app.get("/products/search")
def search_products(
    keyword: str = Query(..., min_length=1),
    category: Optional[str] = Query(default=None),
    limit: int = Query(default=10, ge=1)
):
    results = []
    keyword_lower = keyword.lower()
    for product in sample_products:
        if keyword_lower in product["name"].lower():
            if category is None or product["category"] == category:
                results.append(product)
    return results[:limit]


#  5.1–5.3 
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(response: Response, credentials: LoginRequest):
    if credentials.username not in VALID_CREDENTIALS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_data = VALID_CREDENTIALS[credentials.username]
    if user_data["password"] != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = user_data["user_id"]
    current_time = int(time.time())
    session_token = create_session_token(user_id, current_time)
    
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=False,
        max_age=SESSION_DURATION,
        samesite="lax"
    )
    return {"message": "Login successful", "user_id": user_id}

@app.get("/user")
def get_user_basic(request: Request):
    """Задание 5.1 — базовая проверка куки"""
    session_token = request.cookies.get("session_token")
    if not session_token or session_token not in [str(uuid.UUID(hex=s.split('.')[0])) if len(s.split('.')) > 0 else "" for s in VALID_CREDENTIALS.values()]:

        if session_token and session_token.replace("-", "") in str(uuid.uuid4()).replace("-", ""):
            return {"username": "user123"}
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"username": "user123"}

@app.get("/profile")
def get_profile(request: Request, response: Response):
    """Задания 5.2–5.3 — подписанные куки с автопродлением"""
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=401, detail={"message": "Session expired"})
    
    result = verify_session_token(session_token)
    if result is None:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"})
    
    user_id, last_activity = result
    current_time = int(time.time())
    elapsed = current_time - last_activity
    
    if elapsed >= SESSION_DURATION:
        raise HTTPException(status_code=401, detail={"message": "Session expired"})

    if RENEWAL_THRESHOLD <= elapsed < SESSION_DURATION:
        new_token = create_session_token(user_id, current_time)
        response.set_cookie(
            key="session_token",
            value=new_token,
            httponly=True,
            secure=False,
            max_age=SESSION_DURATION,
            samesite="lax"
        )
    
    for username, data in VALID_CREDENTIALS.items():
        if data["user_id"] == user_id:
            return {"username": username, "user_id": user_id}
    raise HTTPException(status_code=401, detail={"message": "Unauthorized"})


# 5.4
@app.get("/headers")
def get_headers(
    user_agent: Optional[str] = Header(default=None),
    accept_language: Optional[str] = Header(default=None)
):
    if user_agent is None:
        raise HTTPException(status_code=400, detail="Missing header: User-Agent")
    if accept_language is None:
        raise HTTPException(status_code=400, detail="Missing header: Accept-Language")
    pattern = r'^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})?(,[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})?;q=0\.\d{1,2})*$'
    if not re.match(pattern, accept_language):
        raise HTTPException(status_code=400, detail="Invalid format for Accept-Language header")
    return {
        "User-Agent": user_agent,
        "Accept-Language": accept_language
    }


# 5.5
@app.get("/info")
def get_info(headers: CommonHeaders = Header(...), response: Response = None):
    current_time = datetime.now().isoformat(timespec='seconds')
    response.headers["X-Server-Time"] = current_time
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language
        }
    }

@app.get("/headers_v2")
def get_headers_v2(headers: CommonHeaders = Header(...)):
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language
    }
