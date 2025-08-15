import os, base64, hashlib, secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException, Form, Security
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

from passlib.hash import bcrypt
import jwt

# ------------------ Config ------------------
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me-admin")
ACCESS_TOKEN_EXPIRES_IN = int(os.getenv("ACCESS_TOKEN_EXPIRES_IN", "3600"))
REFRESH_TOKEN_EXPIRES_IN = int(os.getenv("REFRESH_TOKEN_EXPIRES_IN", "1209600"))
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "customgpt-demo")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "change-me-client-secret")
ALLOW_REDIRECT_PREFIX = os.getenv("ALLOW_REDIRECT_PREFIX", "https://chat.openai.com/")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://fin-gpt-fastapi.onrender.com")
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")

# ------------------ App ---------------------
app = FastAPI(title="FIN-GPT FastAPI OAuth Demo", version="1.0.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=60*30, same_site="lax")

templates = Jinja2Templates(directory="app/templates")

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ------------------ Security ----------------
http_bearer = HTTPBearer(auto_error=True)

# ------------------ Request Models ----------
class AdminAddRedirectRequest(BaseModel):
    client_id: str
    redirect_uri: str
    admin_token: str  # pass ADMIN_TOKEN in the JSON body (not a header)

# ------------------ Models ------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    phone = Column(String, nullable=True)
    client_code = Column(String, nullable=True)
    name = Column(String, nullable=True)
    trades = relationship("Trade", back_populates="user")
    ledger = relationship("LedgerEntry", back_populates="user")
    holdings = relationship("Holding", back_populates="user")
    pnl = relationship("PnL", back_populates="user")
    funds = relationship("Fund", back_populates="user")

class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    id = Column(Integer, primary_key=True)
    client_id = Column(String, unique=True, nullable=False)
    client_secret = Column(String, nullable=True)
    name = Column(String, default="CustomGPT Client")
    allowed_redirect_prefix = Column(String, default=ALLOW_REDIRECT_PREFIX)
    scope = Column(String, default="read")

class OAuthAuthCode(Base):
    __tablename__ = "oauth_auth_codes"
    id = Column(Integer, primary_key=True)
    code = Column(String, unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    scope = Column(String, default="read")
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    code_challenge = Column(String, nullable=False)
    code_challenge_method = Column(String, default="S256")

class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    id = Column(Integer, primary_key=True)
    access_token = Column(String, unique=True, nullable=False)
    refresh_token = Column(String, unique=True, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(String, nullable=False)
    scope = Column(String, default="read")
    created_at = Column(DateTime, default=datetime.utcnow)
    access_expires_at = Column(DateTime, nullable=False)
    refresh_expires_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)

class Trade(Base):
    __tablename__ = "trades"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    symbol = Column(String, nullable=False)
    side = Column(String, nullable=False)  # BUY/SELL
    qty = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="trades")

class LedgerEntry(Base):
    __tablename__ = "ledger"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    entry_type = Column(String)  # CREDIT/DEBIT
    amount = Column(Float)
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="ledger")

class PnL(Base):
    __tablename__ = "pnl"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(String)  # YYYY-MM-DD
    realized = Column(Float, default=0.0)
    unrealized = Column(Float, default=0.0)
    user = relationship("User", back_populates="pnl")

class Holding(Base):
    __tablename__ = "holdings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    symbol = Column(String)
    qty = Column(Integer)
    avg_price = Column(Float)
    user = relationship("User", back_populates="holdings")

class Fund(Base):
    __tablename__ = "funds"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    available = Column(Float, default=0.0)
    margin_used = Column(Float, default=0.0)
    user = relationship("User", back_populates="funds")

# ------------------ DB utils ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    if db.query(User).count() == 0:
        def mkuser(email, name, phone, code):
            u = User(email=email, name=name, phone=phone, client_code=code, password_hash=bcrypt.hash("test1234"))
            db.add(u); db.flush()
            db.add_all([
                Trade(user_id=u.id, symbol="NIFTY", side="BUY", qty=50, price=24500.0),
                Trade(user_id=u.id, symbol="RELIANCE", side="SELL", qty=10, price=2980.5),
            ])
            db.add_all([
                LedgerEntry(user_id=u.id, entry_type="CREDIT", amount=50000, description="Initial deposit"),
                LedgerEntry(user_id=u.id, entry_type="DEBIT", amount=1500, description="Brokerage & charges"),
            ])
            db.add_all([
                PnL(user_id=u.id, date="2025-08-12", realized=1200.5, unrealized=300.0),
                PnL(user_id=u.id, date="2025-08-13", realized=-350.0, unrealized=100.0),
            ])
            db.add_all([
                Holding(user_id=u.id, symbol="TCS", qty=5, avg_price=3775.0),
                Holding(user_id=u.id, symbol="HDFCBANK", qty=12, avg_price=1540.0),
            ])
            db.add(Fund(user_id=u.id, available=25000.0, margin_used=5000.0))

        mkuser("arun@example.com", "Arun", "+91-90000", "ARUN01")
        mkuser("riya@example.com", "Riya", "+91-90001", "RIYA01")
        mkuser("vikky@example.com", "Vikky", "+91-90002", "VIKKY01")
        db.commit()

    if db.query(OAuthClient).filter_by(client_id=OAUTH_CLIENT_ID).first() is None:
        db.add(OAuthClient(
            client_id=OAUTH_CLIENT_ID,
            client_secret=OAUTH_CLIENT_SECRET,
            name="CustomGPT Client",
            allowed_redirect_prefix=ALLOW_REDIRECT_PREFIX,
            scope="read"
        ))
        db.commit()
    db.close()

init_db()

# ------------------ Token helpers -----------
def create_access_token(user: User, client_id: str, scope: str="read"):
    now = datetime.utcnow()
    exp = now + timedelta(seconds=ACCESS_TOKEN_EXPIRES_IN)
    payload = {
        "sub": str(user.id), "email": user.email, "name": user.name,
        "scope": scope, "client_id": client_id,
        "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "iss": "fin-gpt-fastapi"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token, exp

def create_refresh_token(user: User, client_id: str, scope: str="read"):
    now = datetime.utcnow()
    exp = now + timedelta(seconds=REFRESH_TOKEN_EXPIRES_IN)
    payload = {
        "sub": str(user.id), "scope": scope, "client_id": client_id, "type": "refresh",
        "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "iss": "fin-gpt-fastapi"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token, exp

def verify_bearer_token(db: Session, token: str) -> User:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = int(data.get("sub"))
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    tok = db.query(OAuthToken).filter_by(access_token=token, revoked=False).first()
    if not tok or tok.access_expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Token invalidated")
    return user

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(http_bearer), db: Session = Depends(get_db)) -> User:
    token = credentials.credentials
    return verify_bearer_token(db, token)

# ------------------ Views -------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return "<html><body><h3>FIN-GPT FastAPI OAuth Demo</h3><ul><li><a href='/docs'>API docs</a></li><li><a href='/openapi.json'>OpenAPI</a></li></ul></body></html>"

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# -------- Login & Consent (interactive) -----
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/"):
    return templates.TemplateResponse("login.html", {"request": request, "next": next, "error": None})

@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, email: str = Form(...), password: str = Form(...), next: str = Form("/")):
    db = SessionLocal()
    user = db.query(User).filter_by(email=email).first()
    if not user or not bcrypt.verify(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "next": next, "error": "Invalid credentials"})
    request.session["user_id"] = user.id
    return RedirectResponse(next, status_code=302)

# ------------------ OAuth: authorize --------
def _ensure_client_and_redirect(db: Session, client_id: str, redirect_uri: str) -> OAuthClient:
    client = db.query(OAuthClient).filter_by(client_id=client_id).first()
    if not client:
        raise HTTPException(400, "Unknown client_id")
    if not redirect_uri.startswith(client.allowed_redirect_prefix):
        raise HTTPException(400, "redirect_uri not allowed")
    return client

@app.get("/oauth/authorize", response_class=HTMLResponse)
def oauth_authorize_get(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "read",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: str = "S256",
):
    if response_type != "code":
        raise HTTPException(400, "response_type must be 'code'")
    if not code_challenge or code_challenge_method != "S256":
        raise HTTPException(400, "PKCE S256 required")

    db = SessionLocal()
    _ = _ensure_client_and_redirect(db, client_id, redirect_uri)

    user_id = request.session.get("user_id")
    if not user_id:
        next_url = str(request.url)
        return RedirectResponse(f"/login?next={next_url}", status_code=302)

    txid = secrets.token_urlsafe(16)
    request.session["tx"] = {
        "txid": txid, "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": scope, "state": state,
        "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
    }
    return templates.TemplateResponse("consent.html", {"request": request, "txid": txid, "client_id": client_id, "client_name": "CustomGPT Client", "scope": scope})

@app.post("/oauth/authorize", response_class=HTMLResponse)
def oauth_authorize_post(request: Request, decision: str = Form(...), transaction_id: str = Form(...)):
    tx = request.session.get("tx")
    user_id = request.session.get("user_id")
    if not tx or not user_id or tx.get("txid") != transaction_id:
        raise HTTPException(400, "Invalid transaction")

    if decision != "approve":
        uri = tx["redirect_uri"]; state = tx.get("state"); sep = "&" if "?" in uri else "?"
        return RedirectResponse(f"{uri}{sep}error=access_denied" + (f"&state={state}" if state else ""), status_code=302)

    db = SessionLocal()
    client = _ensure_client_and_redirect(db, tx["client_id"], tx["redirect_uri"])
    code = secrets.token_urlsafe(32)
    db.add(OAuthAuthCode(
        code=code, user_id=user_id, client_id=client.client_id, redirect_uri=tx["redirect_uri"],
        scope=tx["scope"], expires_at=datetime.utcnow() + timedelta(minutes=10),
        code_challenge=tx["code_challenge"], code_challenge_method=tx["code_challenge_method"],
    ))
    db.commit()

    uri = tx["redirect_uri"]; state = tx.get("state"); sep = "&" if "?" in uri else "?"
    redirect = f"{uri}{sep}code={code}" + (f"&state={state}" if state else "")
    request.session.pop("tx", None)
    return RedirectResponse(redirect, status_code=302)

# ------------------ OAuth: token ------------
@app.post("/oauth/token")
def oauth_token(
    request: Request,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
):
    db = SessionLocal()

    if grant_type == "authorization_code":
        if not (code and redirect_uri and code_verifier and client_id):
            raise HTTPException(400, "Missing parameters for authorization_code")
        client = db.query(OAuthClient).filter_by(client_id=client_id).first()
        if not client:
            raise HTTPException(400, "Invalid client_id")
        if client.client_secret and client_secret != client.client_secret:
            raise HTTPException(401, "Invalid client_secret")

        ac = db.query(OAuthAuthCode).filter_by(code=code, client_id=client_id).first()
        if not ac:
            raise HTTPException(400, "Invalid code")
        if ac.expires_at < datetime.utcnow():
            raise HTTPException(400, "Code expired")
        if ac.redirect_uri != redirect_uri:
            raise HTTPException(400, "redirect_uri mismatch")

        # PKCE S256 verify
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        calc_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if calc_challenge != ac.code_challenge:
            raise HTTPException(400, "Invalid code_verifier")

        user = db.get(User, ac.user_id)
        access_token, access_exp = create_access_token(user, client_id=client.client_id, scope=ac.scope)
        refresh_tok, refresh_exp = create_refresh_token(user, client_id=client.client_id, scope=ac.scope)

        db.add(OAuthToken(
            access_token=access_token, refresh_token=refresh_tok, user_id=user.id, client_id=client.client_id,
            scope=ac.scope, access_expires_at=access_exp, refresh_expires_at=refresh_exp
        ))
        db.delete(ac); db.commit()

        return {
            "access_token": access_token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_EXPIRES_IN,
            "refresh_token": refresh_tok, "scope": ac.scope
        }

    elif grant_type == "refresh_token":
        if not refresh_token or not client_id:
            raise HTTPException(400, "Missing parameters for refresh_token")
        client = db.query(OAuthClient).filter_by(client_id=client_id).first()
        if not client:
            raise HTTPException(400, "Invalid client_id")
        tok = db.query(OAuthToken).filter_by(refresh_token=refresh_token, client_id=client_id, revoked=False).first()
        if not tok:
            raise HTTPException(400, "Invalid refresh_token")
        if tok.refresh_expires_at and tok.refresh_expires_at < datetime.utcnow():
            raise HTTPException(400, "Refresh token expired")
        user = db.get(User, tok.user_id)
        new_access, access_exp = create_access_token(user, client_id=client.client_id, scope=tok.scope)
        tok.access_token = new_access; tok.access_expires_at = access_exp; db.commit()
        return {"access_token": new_access, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_EXPIRES_IN, "scope": tok.scope}

    else:
        raise HTTPException(400, "Unsupported grant_type")

# ------------------ OAuth: userinfo ---------
@app.get("/oauth/userinfo")
def oauth_userinfo(user: User = Depends(get_current_user)):
    return {"sub": str(user.id), "email": user.email, "name": user.name, "phone": user.phone, "client_code": user.client_code}

# ------------------ Admin (hidden from schema)
@app.post("/internal/admin/add_redirect", include_in_schema=False)
def internal_admin_add_redirect(payload: AdminAddRedirectRequest, db: Session = Depends(get_db)):
    if payload.admin_token != ADMIN_TOKEN:
        raise HTTPException(403, "Admin token required")
    client = db.query(OAuthClient).filter_by(client_id=payload.client_id).first()
    if not client:
        raise HTTPException(404, "Client not found")
    client.allowed_redirect_prefix = payload.redirect_uri if payload.redirect_uri.endswith("/") else payload.redirect_uri
    db.commit()
    return {"ok": True, "allowed_redirect_prefix": client.allowed_redirect_prefix}

# ------------------ Protected API -----------
@app.get("/api/me")
def api_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"email": user.email, "name": user.name, "phone": user.phone, "client_code": user.client_code}

@app.get("/api/trades")
def api_trades(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Trade).filter_by(user_id=user.id).order_by(Trade.timestamp.desc()).all()
    return [{"symbol": r.symbol, "side": r.side, "qty": r.qty, "price": r.price, "timestamp": r.timestamp.isoformat()} for r in rows]

@app.get("/api/pnl")
def api_pnl(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(PnL).filter_by(user_id=user.id).order_by(PnL.date.desc()).all()
    return [{"date": r.date, "realized": r.realized, "unrealized": r.unrealized} for r in rows]

@app.get("/api/ledger")
def api_ledger(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(LedgerEntry).filter_by(user_id=user.id).order_by(LedgerEntry.timestamp.desc()).all()
    return [{"entry_type": r.entry_type, "amount": r.amount, "description": r.description, "timestamp": r.timestamp.isoformat()} for r in rows]

@app.get("/api/holdings")
def api_holdings(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Holding).filter_by(user_id=user.id).all()
    return [{"symbol": r.symbol, "qty": r.qty, "avg_price": r.avg_price} for r in rows]

@app.get("/api/funds")
def api_funds(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.query(Fund).filter_by(user_id=user.id).first()
    return {"available": (row.available if row else 0.0), "margin_used": (row.margin_used if row else 0.0)}

# ------------------ OpenAPI servers ---------
original_openapi = app.openapi
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = original_openapi()
    schema["servers"] = [{"url": PUBLIC_BASE_URL}]
    app.openapi_schema = schema
    return app.openapi_schema
app.openapi = custom_openapi
