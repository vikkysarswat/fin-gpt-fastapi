from datetime import datetime, timedelta
import os
import secrets
import hashlib
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Float, ForeignKey, Text
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

import jwt  # PyJWT

# -----------------------------
# Config
# -----------------------------
DATABASE_URL = "sqlite:///./app.db"
SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "changeme")

# -----------------------------
# DB setup
# -----------------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -----------------------------
# Models
# -----------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)

    trades = relationship("Trade", back_populates="user")
    ledger = relationship("Ledger", back_populates="user")
    pnl = relationship("PNL", back_populates="user")

class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    id = Column(Integer, primary_key=True)
    client_id = Column(String, unique=True, index=True, nullable=False)
    redirect_uri = Column(String, nullable=False)
    name = Column(String, nullable=True)

class AuthCode(Base):
    __tablename__ = "auth_codes"
    id = Column(Integer, primary_key=True)
    code = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    state = Column(String, nullable=True)

class Trade(Base):
    __tablename__ = "trades"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    symbol = Column(String, nullable=False)
    side = Column(String, nullable=False)  # BUY/SELL
    qty = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="trades")

class Ledger(Base):
    __tablename__ = "ledger"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    date = Column(DateTime, default=datetime.utcnow)
    description = Column(Text, nullable=False)
    amount = Column(Float, nullable=False)

    user = relationship("User", back_populates="ledger")

class PNL(Base):
    __tablename__ = "pnl"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    date = Column(DateTime, default=datetime.utcnow)
    realized_pnl = Column(Float, default=0.0)
    unrealized_pnl = Column(Float, default=0.0)
    mtm_pnl = Column(Float, default=0.0)

    user = relationship("User", back_populates="pnl")

# -----------------------------
# Utility functions
# -----------------------------

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    salt = "static_salt_for_demo_only"  # for demo; consider bcrypt in production
    return hashlib.sha256((salt + password).encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# -----------------------------
# Pydantic Schemas
# -----------------------------
class TradeOut(BaseModel):
    id: int
    symbol: str
    side: str
    qty: int
    price: float
    timestamp: datetime

    class Config:
        from_attributes = True

class LedgerOut(BaseModel):
    id: int
    date: datetime
    description: str
    amount: float

    class Config:
        from_attributes = True

class PNLOut(BaseModel):
    id: int
    date: datetime
    realized_pnl: float
    unrealized_pnl: float
    mtm_pnl: float

    class Config:
        from_attributes = True

class UserInfo(BaseModel):
    email: str
    full_name: Optional[str] = None

# -----------------------------
# FastAPI app & Security
# -----------------------------

app = FastAPI(
    title="CustomGPT Finance Demo API",
    description="Simple OAuth2 + SQLite backend for CustomGPT Actions. Two demo users with stock data.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 scheme for OpenAPI (note: actual validation is manual below)
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{BASE_URL}/oauth/authorize",
    tokenUrl=f"{BASE_URL}/oauth/token",
)

# -----------------------------
# Startup: create tables & seed data
# -----------------------------

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed users if not present
        if not db.query(User).filter_by(email="arun@example.com").first():
            db.add(User(email="arun@example.com", full_name="Arun Kumar", password_hash=hash_password("test1234")))
        if not db.query(User).filter_by(email="vikky@example.com").first():
            db.add(User(email="vikky@example.com", full_name="Vikky Saraswat", password_hash=hash_password("test1234")))
        db.commit()

        # Seed OAuth client (demo)
        if not db.query(OAuthClient).filter_by(client_id="customgpt-demo").first():
            db.add(OAuthClient(
                client_id="customgpt-demo",
                redirect_uri="https://chat.openai.com/aip/placeholder/oauth/callback",
                name="CustomGPT Demo Client"
            ))
            db.commit()

        # Seed some data for each user
        for email in ("arun@example.com", "vikky@example.com"):
            user = db.query(User).filter_by(email=email).first()
            if user and not db.query(Trade).filter_by(user_id=user.id).first():
                # Trades
                db.add_all([
                    Trade(user_id=user.id, symbol="NSE:NIFTY", side="BUY", qty=50, price=24350.0),
                    Trade(user_id=user.id, symbol="NSE:RELIANCE", side="SELL", qty=10, price=2900.5),
                ])
                # Ledger
                db.add_all([
                    Ledger(user_id=user.id, description="Funds added", amount=50000.0),
                    Ledger(user_id=user.id, description="Brokerage fee", amount=-120.5),
                ])
                # PnL
                db.add_all([
                    PNL(user_id=user.id, realized_pnl=1250.5, unrealized_pnl=300.0, mtm_pnl=1550.5),
                    PNL(user_id=user.id, realized_pnl=-350.0, unrealized_pnl=120.0, mtm_pnl=-230.0),
                ])
                db.commit()
    finally:
        db.close()

# -----------------------------
# Helpers
# -----------------------------

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    # Expect Authorization: Bearer <token>
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# -----------------------------
# OAuth2 endpoints
# -----------------------------

@app.get("/oauth/authorize", response_class=HTMLResponse, tags=["oauth2"])
async def oauth_authorize_get(request: Request, client_id: str, redirect_uri: str, state: Optional[str] = None, response_type: str = "code"):
    # Validate client_id & redirect
    with SessionLocal() as db:
        client = db.query(OAuthClient).filter_by(client_id=client_id).first()
        if not client:
            return HTMLResponse(f"<h3>Invalid client_id</h3>")
        if not redirect_uri.startswith("https://chat.openai.com/aip/") or not redirect_uri.endswith("/oauth/callback"):
            # For safety, only allow ChatGPT CustomGPT callbacks by default
            return HTMLResponse("<h3>Invalid redirect_uri</h3>")

    # Simple login form
    return HTMLResponse(
        f"""
        <html><head><title>Sign in</title></head>
        <body style='font-family: sans-serif;'>
        <h2>Sign in to allow access</h2>
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="client_id" value="{client_id}"/>
            <input type="hidden" name="redirect_uri" value="{redirect_uri}"/>
            <input type="hidden" name="state" value="{state or ''}"/>
            <label>Email</label><br/>
            <input name="email" type="email" placeholder="email" required/><br/><br/>
            <label>Password</label><br/>
            <input name="password" type="password" placeholder="password" required/><br/><br/>
            <button type="submit">Sign in & Authorize</button>
        </form>
        <p>Demo users: arun@example.com / test1234, vikky@example.com / test1234</p>
        </body></html>
        """
    )

@app.post("/oauth/authorize", response_class=HTMLResponse, tags=["oauth2"])
async def oauth_authorize_post(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    state: Optional[str] = Form(None),
):
    with SessionLocal() as db:
        client = db.query(OAuthClient).filter_by(client_id=client_id).first()
        if not client:
            return HTMLResponse("<h3>Invalid client_id</h3>")
        if not redirect_uri.startswith("https://chat.openai.com/aip/") or not redirect_uri.endswith("/oauth/callback"):
            return HTMLResponse("<h3>Invalid redirect_uri</h3>")

        user = db.query(User).filter_by(email=email).first()
        if not user or not verify_password(password, user.password_hash):
            return HTMLResponse("<h3>Invalid credentials</h3>")

        # Create one-time code
        code = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        db.add(AuthCode(code=code, user_id=user.id, client_id=client_id, expires_at=expires_at, state=state or ""))
        db.commit()

    # Redirect back to CustomGPT callback
    url = f"{redirect_uri}?code={code}"
    if state:
        url += f"&state={state}"
    return RedirectResponse(url)

@app.post("/oauth/token", tags=["oauth2"])
async def oauth_token(grant_type: str = Form(...), code: str = Form(...), redirect_uri: str = Form(...), client_id: str = Form(...)):
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    with SessionLocal() as db:
        row = db.query(AuthCode).filter_by(code=code, client_id=client_id).first()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid code")
        if row.expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Code expired")

        user = db.query(User).filter_by(id=row.user_id).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        # Consume code (one-time use)
        db.delete(row)
        db.commit()

    access_token = create_access_token({"sub": user.email})
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

# -----------------------------
# Admin endpoint to add client ids
# -----------------------------
class AddClientIn(BaseModel):
    client_id: str
    redirect_uri: str
    name: Optional[str] = None

@app.post("/internal/admin/add_client")
def add_client(in_: AddClientIn, request: Request, db: Session = Depends(get_db)):
    if request.headers.get("x-admin-token") != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden: bad admin token")
    if db.query(OAuthClient).filter_by(client_id=in_.client_id).first():
        return {"status": "exists", "client_id": in_.client_id}
    db.add(OAuthClient(client_id=in_.client_id, redirect_uri=in_.redirect_uri, name=in_.name))
    db.commit()
    return {"status": "ok", "client_id": in_.client_id}

# -----------------------------
# User info & protected resources
# -----------------------------
@app.get("/me", response_model=UserInfo, tags=["data"])  # handy for testing
def me(user: User = Depends(get_current_user)):
    return UserInfo(email=user.email, full_name=user.full_name)

@app.get("/trades", response_model=List[TradeOut], tags=["data"], dependencies=[Depends(oauth2_scheme)])
def get_trades(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Trade).filter_by(user_id=user.id).order_by(Trade.timestamp.desc()).all()

@app.get("/ledger", response_model=List[LedgerOut], tags=["data"], dependencies=[Depends(oauth2_scheme)])
def get_ledger(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Ledger).filter_by(user_id=user.id).order_by(Ledger.date.desc()).all()

@app.get("/pnl", response_model=List[PNLOut], tags=["data"], dependencies=[Depends(oauth2_scheme)])
def get_pnl(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(PNL).filter_by(user_id=user.id).order_by(PNL.date.desc()).all()

# Root
@app.get("/")
def root():
    return {"status": "ok", "message": "CustomGPT Finance Demo API", "base_url": BASE_URL}

