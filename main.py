import os
import re
import html
import base64
import binascii
import hmac
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List, Optional, Dict, Any, Tuple
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Query,
    Path,
    status,
    Security,
    Form,
    Request,
)
from fastapi.security import (
    OAuth2PasswordBearer,
    SecurityScopes,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.exc import UnknownHashError
from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    SmallInteger,
    String,
    Numeric,
    DateTime,
    Boolean,
    select,
    insert,
    update,
    delete,
    text,
    Float,
    Text,
)
from sqlalchemy.orm import sessionmaker, Session
# ------------------------------------------------------------------------------------------------
# Quick notes for runtime robustness
# - Pin bcrypt to 4.0.1 when using passlib (bcrypt>=4.1 can break passlib<1.7.5) in some envs.
# Example requirements: passlib==1.7.4, bcrypt==4.0.1, python-jose[cryptography]==3.3.0
# - Required env vars: SECRET_KEY, CRED_ENC_KEY, DB_URL (or DATABASE_URL / DATABASE_INTERNAL_URL)
# ------------------------------------------------------------------------------------------------
# Auto-load .env for local/dev runs (safe no-op in prod)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass
# ------------------------------------------------------------------------------------------------
# FastAPI App (with ordered tags for a clean Swagger UI)
# ------------------------------------------------------------------------------------------------
tags_metadata = [
    {"name": "Items", "description": "CRUD for Items with List and Search."},
    {"name": "Extras", "description": "CRUD for Extras with List and Search."},
    {"name": "Car Control", "description": "CRUD for Car Control with List and Search."},
    {"name": "Users", "description": "User management and per-user keys."},
    {"name": "Auth", "description": "Token and logout endpoints."},
    {"name": "System", "description": "Health checks and diagnostics."},
]

app = FastAPI(title="Bugzy Test API Development", openapi_tags=tags_metadata)
# CORS (configure via env CORS_ORIGINS="*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Dark-mode Swagger UI (reliable and high-contrast) ----
@app.get("/swagger-dark.css", include_in_schema=False)
def swagger_dark_css():
    css = """
@import url('https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui.css');
:root {
  color-scheme: dark;
  --bg:#0d1117;
  --text:#e6edf3;
  --muted:#c3cbd3;
  --panel:#0f172a;
  --panel-2:#111827;
  --summary:#1f2937;
  --border:#374151;
  --code:#0b1220;
  --link:#93c5fd;
  --get:#3b82f6; --post:#22c55e; --put:#f59e0b; --delete:#ef4444; --patch:#a855f7;
}
html,body,.swagger-ui{background-color:var(--bg)!important;color:var(--text)!important;}
.swagger-ui .topbar{background:var(--panel-2)!important;border-bottom:1px solid var(--border)!important;}
.swagger-ui .info,.swagger-ui .markdown,.swagger-ui .markdown p,.swagger-ui .info .title,.swagger-ui .title,.swagger-ui .opblock-tag{color:var(--text)!important;}
.swagger-ui .opblock{background:var(--panel)!important;border-color:var(--border)!important;box-shadow:none!important;}
.swagger-ui .opblock .opblock-summary{background:var(--summary)!important;color:var(--text)!important;}
.swagger-ui .opblock-summary-method{background:transparent!important;border:1px solid var(--border)!important;color:var(--text)!important;}
.swagger-ui .opblock-summary-path,.swagger-ui .opblock-summary-path__deprecated,.swagger-ui .opblock-summary-description{color:var(--text)!important;}
.swagger-ui .opblock-description-wrapper,.swagger-ui .opblock-external-docs-wrapper{color:var(--text)!important;}
.swagger-ui .opblock.opblock-get{border-left:4px solid var(--get)!important;}
.swagger-ui .opblock.opblock-post{border-left:4px solid var(--post)!important;}
.swagger-ui .opblock.opblock-put{border-left:4px solid var(--put)!important;}
.swagger-ui .opblock.opblock-delete{border-left:4px solid var(--delete)!important;}
.swagger-ui .opblock.opblock-patch{border-left:4px solid var(--patch)!important;}
.swagger-ui .parameters,.swagger-ui .request-body,.swagger-ui .responses-wrapper,.swagger-ui .responses-inner,
.swagger-ui .response,.swagger-ui .model,.swagger-ui .model-box,.swagger-ui .model-box .model-jump-to-path{
  background:var(--panel-2)!important;color:var(--text)!important;border-color:var(--border)!important;
}
.swagger-ui table thead tr,.swagger-ui table tbody tr{background:var(--panel-2)!important;color:var(--text)!important;}
.swagger-ui table thead tr th,.swagger-ui table tbody tr td{border-color:var(--border)!important;color:var(--text)!important;}
.swagger-ui .parameter__name,.swagger-ui .parameter__type,.swagger-ui .prop-format,.swagger-ui .parameter__in,
.swagger-ui .model-title__text,.swagger-ui .prop-type,.swagger-ui .model .property .prop-type{color:var(--muted)!important;}
.swagger-ui .btn,.swagger-ui select,.swagger-ui input,.swagger-ui textarea{
  background:var(--code)!important;color:var(--text)!important;border:1px solid var(--border)!important;box-shadow:none!important;
}
.swagger-ui .btn.authorize span{color:var(--text)!important;}
.swagger-ui ::placeholder{color:#9ca3af!important;}
.swagger-ui .response-col_status,.swagger-ui .response-col_description{color:var(--text)!important;}
.swagger-ui .tab li,.swagger-ui .tab li a{color:var(--text)!important;}
.swagger-ui .markdown code,.swagger-ui code,.swagger-ui pre{background:var(--code)!important;color:var(--text)!important;border:1px solid var(--border)!important;}
.swagger-ui a{color:var(--link)!important;} .swagger-ui a:hover{color:#bfdbfe!important;}
.swagger-ui .model-toggle,.swagger-ui .model-box-control,.swagger-ui .expand-operation{color:var(--muted)!important;}
.swagger-ui .arrow,.swagger-ui .expand-methods svg,.swagger-ui .expand-operation svg{fill:var(--muted)!important;stroke:var(--muted)!important;}
"""
    return Response(content=css, media_type="text/css")

@app.get("/docs-dark", include_in_schema=False)
def docs_dark():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Docs (Dark)",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js",
        swagger_css_url="/swagger-dark.css?v=2",  # cache-bust to ensure latest CSS loads
        swagger_favicon_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/favicon-32x32.png",
    )

# ------------------------------------------------------------------------------------------------
# Database (Render-friendly env vars + scheme normalization)
# ------------------------------------------------------------------------------------------------
def _resolve_db_url() -> str:
    raw = (
        os.getenv("DB_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("DATABASE_INTERNAL_URL")
        or ""
    ).strip()
    if not raw:
        raise RuntimeError(
            "DB_URL is required (no hardcoded defaults). "
            "Set DB_URL or DATABASE_URL or DATABASE_INTERNAL_URL."
        )
    raw = html.unescape(raw)
    # Normalize legacy postgres:// scheme
    if raw.startswith("postgres://"):
        raw = raw.replace("postgres://", "postgresql+psycopg2://", 1)
    return raw
DB_URL = _resolve_db_url()
engine = create_engine(DB_URL, future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
metadata = MetaData()
# ------------------------------------------------------------------------------------------------
# OAuth2 / JWT configuration
# ------------------------------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is required.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
# -- Encryption for credential JSON (Fernet) --
# CRED_ENC_KEY must be a base64 urlsafe 32-byte key (Fernet)
# Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
from cryptography.fernet import Fernet  # noqa: E402
CRED_ENC_KEY = os.getenv("CRED_ENC_KEY") or os.getenv("ENCRYPTION_KEY")
if not CRED_ENC_KEY:
    raise RuntimeError(
        "CRED_ENC_KEY is required for encrypted credential downloads. "
        "Generate with Fernet.generate_key() and set as env var."
    )
# Optional key id (useful when rotating keys)
CRED_ENC_KID = os.getenv("CRED_ENC_KID", "k1")
_fernet = Fernet(CRED_ENC_KEY.encode() if isinstance(CRED_ENC_KEY, str) else CRED_ENC_KEY)
def _enc_value(v: str) -> str:
    return _fernet.encrypt(v.encode("utf-8")).decode("utf-8")
def _dec_value(v: str) -> str:
    """Decrypt a Fernet token string to plaintext. Raises if invalid."""
    return _fernet.decrypt(v.encode("utf-8")).decode("utf-8")
def _value_is_fernet_token(v: str) -> bool:
    """Best-effort check: return True if v is a valid Fernet token for our key."""
    try:
        _fernet.decrypt(v.encode("utf-8"))
        return True
    except Exception:
        return False
def _decrypt_fields(d: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    """Return a copy with any Fernet token values in `fields` decrypted to plaintext."""
    out = dict(d)
    for k in fields:
        val = out.get(k)
        if isinstance(val, str) and val.strip() and _value_is_fernet_token(val):
            out[k] = _dec_value(val)
    return out
SENSITIVE_KEYS = ["ci", "cs", "pu", "ot", "saak", "sask"]
def _encrypt_fields(d: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    out = dict(d)
    encd: List[str] = []
    for k in fields:
        val = out.get(k)
        if val is None:
            continue
        sval = str(val).strip()
        if not sval:
            continue
        # Prevent double-encryption (saak/sask may be encrypted at rest)
        if _value_is_fernet_token(sval):
            continue
        out[k] = _enc_value(sval)
        encd.append(k)
    if encd:
        meta = out.get("_meta", {})
        meta.update({"enc": "fernet-v1", "enc_keys": encd, "kid": CRED_ENC_KID})
        out["_meta"] = meta
    return out
# ------------------------------------------------------------------------------------------------
# Token Revocation Logic (in-memory per-token + token_version in DB)
# ------------------------------------------------------------------------------------------------
revoked_tokens: Dict[str, datetime] = {}
def _cleanup_revoked_tokens(now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()
    expired = [tok for tok, exp in revoked_tokens.items() if exp <= now]
    for tok in expired:
        revoked_tokens.pop(tok, None)
def revoke_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp:
            revoked_tokens[token] = datetime.utcfromtimestamp(exp)
    except Exception:
        # Ignore malformed tokens
        pass
def is_token_revoked(token: str) -> bool:
    _cleanup_revoked_tokens()
    return token in revoked_tokens
# One (and only one) password hashing implementation — Passlib CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except (UnknownHashError, ValueError):
        # Treat invalid/unknown hash as bad credentials, not server error
        return False
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
SCOPES: Dict[str, str] = {
    "items:read": "Read items",
    "items:write": "Create/update/delete items",
    "extras:read": "Read extras",
    "extras:write": "Create/update/delete extras",
    "cars:read": "Read car_control",
    "cars:write": "Create/update/delete car_control",
    "admin": "Administrative operations",
}
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", scopes=SCOPES)
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="token", scopes=SCOPES, auto_error=False)
KNOWN_SCOPES = set(SCOPES.keys())
DEFAULT_USER_SCOPES = os.getenv("DEFAULT_USER_SCOPES", "items:read extras:read cars:read").split()
OPEN_USER_REGISTRATION = os.getenv("OPEN_USER_REGISTRATION", "true").lower() == "true"
# ---- Client credential enforcement (env-driven) ----
REQUIRE_CLIENT_AUTH = os.getenv("REQUIRE_CLIENT_AUTH", "false").lower() == "true"
EXPECTED_CLIENT_ID = os.getenv("CLIENT_ID", "")
EXPECTED_CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
def _extract_basic_auth(request: Request) -> Tuple[Optional[str], Optional[str], str]:
    """
    Returns (client_id, client_secret, source) where source in {"basic","missing","basic-invalid"}.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("basic "):
        return (None, None, "missing")
    b64 = auth.split(" ", 1)[1].strip()
    try:
        raw = base64.b64decode(b64).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return (None, None, "basic-invalid")
    if ":" not in raw:
        return (None, None, "basic-invalid")
    cid, csec = raw.split(":", 1)
    return (cid, csec, "basic")
def _get_client_credentials(request: Request, client_id_form: Optional[str], client_secret_form: Optional[str]) -> Tuple[Optional[str], Optional[str], str]:
    """
    Prefer HTTP Basic header; fallback to form fields.
    Returns (client_id, client_secret, source) with source in {"basic","form","missing","basic-invalid"}.
    """
    cid, csec, src = _extract_basic_auth(request)
    if src == "basic":
        return (cid, csec, "basic")
    if client_id_form or client_secret_form:
        return (client_id_form or "", client_secret_form or "", "form")
    return (None, None, src)  # src is "missing" or "basic-invalid"
# ------------------------------------------------------------------------------------------------
# Helpers: scopes & strings
# ------------------------------------------------------------------------------------------------
def normalize_scopes(scopes: Optional[List[str]]) -> List[str]:
    if not scopes:
        return []
    return sorted(set(s for s in scopes if s in KNOWN_SCOPES))
def parse_scopes_str(s: Optional[str]) -> List[str]:
    return [x for x in (s or "").split(" ") if x]
def join_scopes(scopes: List[str]) -> str:
    return " ".join(sorted(set(scopes)))
def parse_scopes_from_form(s: Optional[str]) -> Optional[List[str]]:
    if not s:
        return None
    parts = re.split(r"[\s,]+", s.strip())
    return [p for p in parts if p]
def _strip_str_values(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            v = v.strip()
        out[k] = v
    return out
# ------------------------------------------------------------------------------------------------
# Helpers: parsing textboxes (all inputs are strings in Swagger)
# ------------------------------------------------------------------------------------------------
def _is_blank(x: Optional[str]) -> bool:
    return x is None or (isinstance(x, str) and x.strip() == "")
def as_int(name: str, value: Optional[str], *, required: bool = False) -> Optional[int]:
    if _is_blank(value):
        if required:
            raise HTTPException(status_code=422, detail=f"{name} is required")
        return None
    try:
        return int(value) if value is not None else None
    except Exception:
        raise HTTPException(status_code=422, detail=f"{name} must be an integer")
def as_float(name: str, value: Optional[str], *, required: bool = False) -> Optional[float]:
    if _is_blank(value):
        if required:
            raise HTTPException(status_code=422, detail=f"{name} is required")
        return None
    try:
        return float(value) if value is not None else None
    except Exception:
        raise HTTPException(status_code=422, detail=f"{name} must be a number")
def as_bool(name: str, value: Optional[str], default: Optional[bool] = None) -> Optional[bool]:
    if _is_blank(value):
        return default
    v = value.strip().lower()
    if v in ("1", "true", "t", "yes", "y", "on"):
        return True
    if v in ("0", "false", "f", "no", "n", "off"):
        return False
    raise HTTPException(status_code=422, detail=f"{name} must be a boolean (true/false)")
def as_str_or_none(value: Optional[str]) -> Optional[str]:
    return None if _is_blank(value) else value
# ------------------------------------------------------------------------------------------------
# Pydantic Response Schemas
# ------------------------------------------------------------------------------------------------
class Item(BaseModel):
    id: int
    name: str
    description: str
    price: float
class Extra(BaseModel):
    extras_code: Optional[str] = None
    name: Optional[str] = None
    english_name: Optional[str] = None
    extra_unit: Optional[int] = None
    extra_group: Optional[int] = None
    vat: Optional[float] = None
    vat_code: Optional[str] = None
    inventory: Optional[str] = None
    gl_code: Optional[str] = None
    gl_code_sl: Optional[str] = None
    international_code: Optional[str] = None
    allow_in_cs: Optional[int] = None
    allow_in_web: Optional[int] = None
    allow_in_client: Optional[int] = None
    allow_in_portal: Optional[int] = None
    ext_extra_for: Optional[str] = None
    calculate_vat: Optional[str] = None
    inventory_by_subextra: Optional[int] = None
    sub_extra_lastno: Optional[int] = None
    flat_amount_yn: Optional[str] = None
class CarControl(BaseModel):
    unit_no: Optional[str] = None
    license_no: Optional[str] = None
    company_code: Optional[int] = None
    fleet_assignment: Optional[str] = None
    f_group: Optional[str] = None
    car_make: Optional[int] = None
    model: Optional[int] = None
    color: Optional[str] = None
    car_status: Optional[int] = None
    owner_country: Optional[str] = None
    check_out_date: Optional[str] = None
    check_out_time: Optional[int] = None
    check_out_branach: Optional[int] = None
    check_in_date: Optional[str] = None
    check_in_time: Optional[int] = None
    check_in_branach: Optional[int] = None
    branach: Optional[int] = None
    country: Optional[str] = None
    current_odometer: Optional[int] = None
    out_of_service_reas: Optional[int] = None
    vehicle_type: Optional[str] = None
    parking_lot_code: Optional[int] = None
    parking_space: Optional[int] = None
    sale_cycle: Optional[int] = None
    last_document_type: Optional[str] = None
    last_document_no: Optional[float] = None
    last_suv_agreement: Optional[int] = None
    odometer_after_min: Optional[int] = None
    reserved_to: Optional[str] = None
    garage: Optional[int] = None
    smoke: Optional[str] = None
    telephone: Optional[str] = None
    taxilimo_chauffeur: Optional[str] = None
    prechecked_in_place: Optional[str] = None
    fleet_sub_assignment: Optional[int] = None
    deposit_note: Optional[float] = None
    europcar_company: Optional[str] = None
    petrol_level: Optional[int] = None
    transaction_user: Optional[str] = None
    transaction_date: Optional[str] = None
    transaction_time: Optional[int] = None
    mortgaged_to: Optional[int] = None
    crc_inter_agr: Optional[int] = None
    lease_document: Optional[int] = None
    lease_srno: Optional[int] = None
    lease_document_type: Optional[str] = None
    lease_last_agreement: Optional[int] = None
    lease_last_sub_agrno: Optional[int] = None
    lease_veh_type: Optional[str] = None  # fixed to str for Pydantic
    crc_chauffeur: Optional[str] = None
    location: Optional[int] = None
    sub_status: Optional[int] = None
    promotional_veh: Optional[str] = None
    mark_preready_stat: Optional[str] = None
    yard_no: Optional[int] = None
    awxx_last_update_date: Optional[str] = None
    class Config:
        schema_extra = {
            "example": {
                "unit_no": "100100000",
                "license_no": "6929HJD",
                "company_code": 1,
                "fleet_assignment": "B",
                "f_group": "FFAR",
                "car_make": 10,
                "model": 7,
                "color": "RED",
                "car_status": 7,
                "owner_country": "KSA",
                "check_out_date": "20251001",
                "check_out_time": 48480,
                "check_out_branach": 1,
                "check_in_date": "20251001",
                "check_in_time": 48540,
                "check_in_branach": 1,
                "branach": 1,
                "country": "KSA",
                "current_odometer": 100,
                "out_of_service_reas": 0,
                "vehicle_type": "VT",
                "parking_lot_code": 1,
                "parking_space": 1,
                "sale_cycle": 0,
                "last_document_type": "Y",
                "last_document_no": 1,
                "last_suv_agreement": 1,
                "odometer_after_min": 0,
                "reserved_to": "RSV000000012",
                "garage": 0,
                "smoke": "N",
                "telephone": "0555555555",
                "taxilimo_chauffeur": "NA",
                "prechecked_in_place": "Yard A",
                "fleet_sub_assignment": 0,
                "deposit_note": 0,
                "europcar_company": "N",
                "petrol_level": 0,
                "transaction_user": "BUGZY",
                "transaction_date": "20251001",
                "transaction_time": 0,
                "mortgaged_to": 0,
                "crc_inter_agr": 0,
                "lease_document": 0,
                "lease_srno": 0,
                "lease_document_type": "L",
                "lease_last_agreement": 0,
                "lease_last_sub_agrno": 0,
                "lease_veh_type": "SEDAN",
                "crc_chauffeur": "NA",
                "location": 0,
                "sub_status": 0,
                "promotional_veh": "N",
                "mark_preready_stat": "N",
                "yard_no": 0,
                "awxx_last_update_date": "2025-10-02T07:00:00Z",
            }
        }
def to_item(row: Dict[str, Any]) -> Item:
    price = row["price"]
    if isinstance(price, Decimal):
        price = float(price)
    return Item(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        price=price,
    )
def to_extra(row: Dict[str, Any]) -> Extra:
    r = {k: (v.strip() if isinstance(v, str) else v) for k, v in dict(row).items()}
    if "vat" in r and isinstance(r["vat"], Decimal):
        r["vat"] = float(r["vat"])
    return Extra(**r)
def to_car_control(row: Dict[str, Any]) -> CarControl:
    # Trim trailing spaces from all string fields before returning
    r = {k: (v.rstrip() if isinstance(v, str) else v) for k, v in dict(row).items()}
    return CarControl(**r)
# ------------------------------------------------------------------------------------------------
# SQLAlchemy Core Table Definitions
# ------------------------------------------------------------------------------------------------
items_table = Table(
    "items",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(200), nullable=False),
    Column("description", String, nullable=False),
    Column("price", Numeric(18, 2), nullable=False),
)
extras_table = Table(
    "extras",
    metadata,
    Column("extras_code", String(3), primary_key=True),
    Column("name", String(30)),
    Column("english_name", String(15)),
    Column("extra_unit", Integer),
    Column("extra_group", Integer),
    Column("vat", Numeric(18, 6)),
    Column("vat_code", String(14)),
    Column("inventory", String(1)),
    Column("gl_code", String(20)),
    Column("gl_code_sl", String(20)),
    Column("international_code", String(8)),
    Column("allow_in_cs", Integer),
    Column("allow_in_web", Integer),
    Column("allow_in_client", Integer),
    Column("allow_in_portal", Integer),
    Column("ext_extra_for", String(1)),
    Column("calculate_vat", String(1)),
    Column("inventory_by_subextra", Integer),
    Column("sub_extra_lastno", Integer),
    Column("flat_amount_yn", String(1)),
)
car_control_table = Table(
    "car_control",
    metadata,
    Column("unit_no", String(10), primary_key=True, nullable=True),
    Column("license_no", String(10), nullable=True),
    Column("company_code", SmallInteger, nullable=True),
    Column("fleet_assignment", String(1), nullable=True),
    Column("f_group", String(5), nullable=True),
    Column("car_make", SmallInteger, nullable=True),
    Column("model", Integer, nullable=True),
    Column("color", String(10), nullable=True),
    Column("car_status", SmallInteger, nullable=True),
    Column("owner_country", String(3), nullable=True),
    Column("check_out_date", String(8), nullable=True),
    Column("check_out_time", Integer, nullable=True),
    Column("check_out_branach", Integer, nullable=True),
    Column("check_in_date", String(8), nullable=True),
    Column("check_in_time", Integer, nullable=True),
    Column("check_in_branach", Integer, nullable=True),
    Column("branach", Integer, nullable=True),
    Column("country", String(3), nullable=True),
    Column("current_odometer", Integer, nullable=True),
    Column("out_of_service_reas", SmallInteger, nullable=True),
    Column("vehicle_type", String(2), nullable=True),
    Column("parking_lot_code", SmallInteger, nullable=True),
    Column("parking_space", SmallInteger, nullable=True),
    Column("sale_cycle", SmallInteger, nullable=True),
    Column("last_document_type", String(1), nullable=True),
    Column("last_document_no", Float, nullable=True),
    Column("last_suv_agreement", SmallInteger, nullable=True),
    Column("odometer_after_min", Integer, nullable=True),
    Column("reserved_to", String(12), nullable=True),
    Column("garage", Integer, nullable=True),
    Column("smoke", String(1), nullable=True),
    Column("telephone", String(20), nullable=True),
    Column("taxilimo_chauffeur", String(10), nullable=True),
    Column("prechecked_in_place", String(40), nullable=True),
    Column("fleet_sub_assignment", SmallInteger, nullable=True),
    Column("deposit_note", Float, nullable=True),
    Column("europcar_company", String(1), nullable=True),
    Column("petrol_level", SmallInteger, nullable=True),
    Column("transaction_user", String(15), nullable=True),
    Column("transaction_date", String(8), nullable=True),
    Column("transaction_time", Integer, nullable=True),
    Column("mortgaged_to", Integer, nullable=True),
    Column("crc_inter_agr", Integer, nullable=True),
    Column("lease_document", Integer, nullable=True),
    Column("lease_srno", SmallInteger, nullable=True),
    Column("lease_document_type", String(1), nullable=True),
    Column("lease_last_agreement", Integer, nullable=True),
    Column("lease_last_sub_agrno", SmallInteger, nullable=True),
    Column("lease_veh_type", Text, nullable=True),
    Column("crc_chauffeur", String(10), nullable=True),
    Column("location", SmallInteger, nullable=True),
    Column("sub_status", Integer, nullable=True),
    Column("promotional_veh", String(1), nullable=True),
    Column("mark_preready_stat", String(1), nullable=True),
    Column("yard_no", Integer, nullable=True),
    Column("awxx_last_update_date", String(20), nullable=True),
)
users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True, nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("scopes", String, nullable=True),
    Column("token_version", Integer, nullable=False, server_default=text("1")),
    # per-user keys
    Column("saak", String, nullable=True),
    Column("sask", String, nullable=True),
)
# ------------------------------------------------------------------------------------------------
# DB Session Dependency
# ------------------------------------------------------------------------------------------------
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# ------------------------------------------------------------------------------------------------
# Auth Helpers
# ------------------------------------------------------------------------------------------------
def get_user_by_username(db: Session, username: str) -> Optional[Dict[str, Any]]:
    row = db.execute(
        select(users_table).where(users_table.c.username == username)
    ).mappings().first()
    return dict(row) if row else None
def authenticate_user(db: Session, username: str, password: str) -> Optional[Dict[str, Any]]:
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    if not user.get("is_active", True):
        return None
    return user
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
class User(BaseModel):
    username: str
    is_active: bool = True
def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> "User":
    auth_header = f'Bearer scope="{security_scopes.scope_str}"' if security_scopes.scopes else "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": auth_header},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if is_token_revoked(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": auth_header},
            )
        username: Optional[str] = payload.get("sub")
        token_scopes: List[str] = payload.get("scopes", [])
        token_ver: int = int(payload.get("ver", 1))
        if username is None:
            raise credentials_exception
        for scope in security_scopes.scopes:
            if scope not in token_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": auth_header},
                )
        user_record = get_user_by_username(db, username)
        if not user_record:
            raise credentials_exception
        current_ver = int(user_record.get("token_version", 1))
        if token_ver != current_ver:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": auth_header},
            )
        return User(username=user_record["username"], is_active=user_record.get("is_active", True))
    except JWTError:
        raise credentials_exception
def get_current_active_user(
    current_user: User = Security(get_current_user, scopes=[]),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
def require_admin_if_closed(token: Optional[str], db: Session) -> None:
    if OPEN_USER_REGISTRATION:
        return
    auth_header = 'Bearer scope="admin"'
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": auth_header},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        token_scopes: List[str] = payload.get("scopes", [])
        if (username is None) or ("admin" not in token_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin scope required",
                headers={"WWW-Authenticate": auth_header},
            )
        user_record = get_user_by_username(db, username)
        if not user_record or not user_record.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive user",
                headers={"WWW-Authenticate": auth_header},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": auth_header},
        )
# ------------------------------------------------------------------------------------------------
# Helper Functions (ordering & filters)
# ------------------------------------------------------------------------------------------------
def apply_ordering(query, table, order_by: Optional[str], default_col: str) -> Tuple[Any, Optional[str]]:
    if not order_by:
        col = getattr(table.c, default_col, None)
        if col is not None:
            return query.order_by(col.asc()), f"{default_col}:asc"
        return query, None
    parts = order_by.split(":")
    col_name = parts[0].strip()
    direction = parts[1].strip().lower() if len(parts) > 1 else "asc"
    col = getattr(table.c, col_name, None)
    if col is None:
        return query, None
    if direction not in ("asc", "desc"):
        direction = "asc"
    query = query.order_by(col.asc() if direction == "asc" else col.desc())
    return query, f"{col_name}:{direction}"
def like_or_equals(col, value: Optional[str], partial: bool):
    if value is None:
        return None
    return col.ilike(f"%{value}%") if partial else (col == value)
# ------------------------------------------------------------------------------------------------
# Auth: Token endpoint (now enforces client credentials when enabled)
# ------------------------------------------------------------------------------------------------
@app.post("/token", tags=["Auth"])
def login_for_access_token(
    request: Request,
    username: str = Form(..., example=""),
    password: str = Form(..., example=""),
    scope: Optional[str] = Form("", description="Optional scopes (space separated)", example=""),
    grant_type: Optional[str] = Form("", description="Leave blank (treated as password grant)", example=""),
    # Optional form-based client credentials (for Swagger/manual): Basic header also supported
    client_id: Optional[str] = Form(None, description="Client ID (if REQUIRE_CLIENT_AUTH=true)", example=""),
    client_secret: Optional[str] = Form(None, description="Client secret (if REQUIRE_CLIENT_AUTH=true)", example=""),
    db: Session = Depends(get_db),
):
    # --- Client authentication (if enabled) ---
    if REQUIRE_CLIENT_AUTH:
        if not EXPECTED_CLIENT_ID or not EXPECTED_CLIENT_SECRET:
            # Misconfigured environment
            raise HTTPException(
                status_code=500,
                detail="Client authentication is enabled but CLIENT_ID/CLIENT_SECRET are not configured",
            )
        cid, csec, src = _get_client_credentials(request, client_id, client_secret)
        if cid is None or csec is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client authentication required (send Basic auth header or form client_id/client_secret)",
                headers={"WWW-Authenticate": 'Basic realm="token", charset="UTF-8"'},
            )
        if not (hmac.compare_digest(cid, EXPECTED_CLIENT_ID) and hmac.compare_digest(csec, EXPECTED_CLIENT_SECRET)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials",
                headers={"WWW-Authenticate": 'Basic realm="token", error="invalid_client"'},
            )
    # --- Resource owner password validation ---
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    requested = normalize_scopes(parse_scopes_from_form(scope) or [])
    allowed = normalize_scopes(parse_scopes_str(user.get("scopes")) or DEFAULT_USER_SCOPES)
    granted = requested if requested else allowed
    granted = [s for s in granted if s in allowed and s in KNOWN_SCOPES]
    ver = int(user.get("token_version", 1))
    access_token = create_access_token(
        data={"sub": user["username"], "scopes": granted, "ver": ver}
    )
    return {"access_token": access_token, "token_type": "bearer"}
# ------------------------------------------------------------------------------------------------
# Users: Register (Form-only), Me, Logout
# ------------------------------------------------------------------------------------------------
@app.post("/users/register", status_code=201, tags=["Users"])
def register_user(
    username: str = Form(..., min_length=3, max_length=50, description="Letters, digits, underscore, dot, dash", example=""),
    password: str = Form(..., min_length=8, description="At least 8 characters", example=""),
    scopes_text: Optional[str] = Form("", description="Optional scopes (space/comma separated)", example=""),
    # NOTE: kept for backward-compat but ignored; we always mirror & encrypt username/password into saak/sask
    saak: Optional[str] = Form("", description="(Ignored) User access key", example=""),
    sask: Optional[str] = Form("", description="(Ignored) User secret key", example=""),
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
):
    require_admin_if_closed(token, db)
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{3,50}", username):
        raise HTTPException(
            status_code=422,
            detail="Username must be 3–50 chars; allowed: letters, numbers, underscore, dot, dash",
        )
    exists = db.execute(
        select(users_table.c.id).where(users_table.c.username == username)
    ).scalar()
    if exists is not None:
        raise HTTPException(status_code=409, detail="Username already exists")
    scopes_in = parse_scopes_from_form(scopes_text)
    scopes = normalize_scopes(scopes_in) if scopes_in is not None else normalize_scopes(DEFAULT_USER_SCOPES)
    # -- Store encrypted-at-rest mirrors of entered username/password --
    enc_saak = _enc_value(username.strip())
    enc_sask = _enc_value(password.strip())
    db.execute(
        insert(users_table).values(
            username=username,
            hashed_password=get_password_hash(password),
            is_active=True,
            scopes=join_scopes(scopes),
            token_version=1,
            saak=enc_saak,  # encrypted username
            sask=enc_sask,  # encrypted password
        )
    )
    db.commit()
    return {"username": username, "is_active": True, "scopes": scopes}
@app.get("/users/me", response_model=Dict[str, Any], tags=["Users"])
def read_users_me(
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    rec = db.execute(
        select(users_table).where(users_table.c.username == current_user.username)
    ).mappings().first()
    if not rec:
        raise HTTPException(status_code=404, detail="User not found")
    allowed_scopes = normalize_scopes(parse_scopes_str(rec.get("scopes")))
    return {"username": current_user.username, "is_active": current_user.is_active, "scopes": allowed_scopes}
@app.post("/logout", tags=["Auth"])
def logout_current(
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    db.execute(
        update(users_table)
        .where(users_table.c.username == current_user.username)
        .values(token_version=text("COALESCE(token_version,1) + 1"))
    )
    db.commit()
    return {"message": "Logged out (all tokens invalidated)"}
# ------------------------------------------------------------------------------------------------
# Users: manage per-user keys
# ------------------------------------------------------------------------------------------------
@app.put("/users/me/keys", tags=["Users"])
def update_my_keys(
    saak: Optional[str] = Form("", description="User access key (optional)", example=""),
    sask: Optional[str] = Form("", description="User secret key (optional)", example=""),
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    vals: Dict[str, Any] = {}
    if not _is_blank(saak):
        vals["saak"] = saak.strip()
    if not _is_blank(sask):
        vals["sask"] = sask.strip()
    if not vals:
        raise HTTPException(status_code=422, detail="Provide at least one of saak/sask")
    res = db.execute(
        update(users_table).where(users_table.c.username == current_user.username).values(**vals)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    db.commit()
    return {"username": current_user.username, "updated": list(vals.keys())}
@app.put("/users/{username}/keys", tags=["Users"])
def update_user_keys(
    username: str = Path(..., description="Target username"),
    saak: Optional[str] = Form("", description="User access key (optional)", example=""),
    sask: Optional[str] = Form("", description="User secret key (optional)", example=""),
    _admin: User = Security(get_current_user, scopes=["admin"]),
    db: Session = Depends(get_db),
):
    vals: Dict[str, Any] = {}
    if not _is_blank(saak):
        vals["saak"] = saak.strip()
    if not _is_blank(sask):
        vals["sask"] = sask.strip()
    if not vals:
        raise HTTPException(status_code=422, detail="Provide at least one of saak/sask")
    res = db.execute(update(users_table).where(users_table.c.username == username).values(**vals))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    db.commit()
    return {"username": username, "updated": list(vals.keys())}
# ------------------------------------------------------------------------------------------------
# Users: Download Credentials (JSON only, admin-only list)
# ------------------------------------------------------------------------------------------------
@app.get(
    "/users/credentials/download",
    tags=["Users"],
    summary="Download user credentials (JSON)",
    response_description="JSON file download",
    responses={
        200: {
            "description": "JSON file (download)",
            "content": {"application/json": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
def download_user_credentials_json(
    current_user: User = Security(get_current_user, scopes=["admin"]),
    db: Session = Depends(get_db),
):
    """
    Export NON-SENSITIVE user info only. Excludes hashed_password.
    Columns: id, username, is_active, scopes (as list), token_version
    """
    rows = db.execute(
        select(
            users_table.c.id,
            users_table.c.username,
            users_table.c.is_active,
            users_table.c.scopes,
            users_table.c.token_version,
        )
    ).mappings().all()
    out: List[Dict[str, Any]] = []
    for r in rows:
        scopes_text = (r.get("scopes") or "").strip()
        scopes_list = [s for s in scopes_text.split(" ") if s]
        out.append(
            {
                "id": r["id"],
                "username": r["username"],
                "is_active": bool(r.get("is_active", True)),
                "scopes": scopes_list,
                "token_version": int(r.get("token_version", 1)),
            }
        )
    ts = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f'user_credentials_{ts}.json'
    return JSONResponse(
        content=out,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
# ------------------------------------------------------------------------------------------------
# Credential Builders & Endpoints (short-key JSON, with encryption and plain toggle)
# ------------------------------------------------------------------------------------------------
def _build_api_for_user(user_record: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """
    Build an API short-key credential JSON for Postman/clients.
    Keys included: ti, cn, dt, ci, cs, iu, pu, oa, ot, or, ev, v, saak, sask
    NOTE: Sensitive keys are encrypted in the returned payload unless ?plain=true (admin).
    """
    username = user_record["username"]
    scopes_list = normalize_scopes(parse_scopes_str(user_record.get("scopes")))
    base_url = str(request.base_url).rstrip("/")
    token_full = f"{base_url}/token"
    # Prefer per-user values; fallback to env
    tenant_id = os.getenv("TENANT_ID") or "local"
    client_name = os.getenv("CLIENT_NAME") or f"{username}@{tenant_id}"
    client_id = os.getenv("CLIENT_ID", "")
    client_secret = os.getenv("CLIENT_SECRET", "")
    env_name = os.getenv("ENVIRONMENT", os.getenv("ENV", "DEV"))
    # Per-user keys first
    saak = (user_record.get("saak") or os.getenv("SAAK") or "")
    sask = (user_record.get("sask") or os.getenv("SASK") or "")
    payload = {
        "ti": tenant_id,
        "cn": client_name,
        "dt": "password",  # grant type used by /token in this API
        "ci": client_id,  # sensitive
        "cs": client_secret,  # sensitive
        "iu": base_url,  # left plaintext by design (visible)
        "pu": base_url,  # sensitive-ish (encrypt)
        "oa": token_full,  # left plaintext by design (visible)
        "ot": "token",  # sensitive-ish (encrypt), no leading slash
        "or": "/docs",
        "ev": env_name,
        "v": 1,
        "saak": saak,  # sensitive (may be encrypted-at-rest in DB)
        "sask": sask,  # sensitive (may be encrypted-at-rest in DB)
        # Helpful extras (non-canonical)
        "un": username,
        "scopes": scopes_list,
    }
    return payload
def _encrypt_payload_if_needed(
    payload: Dict[str, Any],
    *,
    do_encrypt: bool,
) -> Dict[str, Any]:
    if not do_encrypt:
        # For plaintext exports: strip meta and DECRYPT any encrypted-at-rest sensitive fields
        cp = dict(payload)
        cp.pop("_meta", None)
        cp = _decrypt_fields(cp, SENSITIVE_KEYS)
        return cp
    # Encrypt only sensitive keys; keep iu/oa visible
    return _encrypt_fields(payload, SENSITIVE_KEYS)
def _caller_is_admin(db: Session, username: str) -> bool:
    rec = db.execute(
        select(users_table.c.scopes).where(users_table.c.username == username)
    ).mappings().first()
    if not rec:
        return False
    scopes_list = normalize_scopes(parse_scopes_str(rec.get("scopes")))
    return "admin" in scopes_list
@app.get(
    "/users/me/credentials/api.json",
    tags=["Users"],
    summary="Download API credentials for current user",
    response_description="API credentials JSON (download)",
    responses={
        200: {
            "description": "JSON file (download)",
            "content": {"application/json": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
def download_my_api_credentials(
    request: Request,
    plain_str: Optional[str] = Query("", alias="plain", description="If true and caller is admin, return plaintext"),
    current_user: User = Security(get_current_user, scopes=[]),
    db: Session = Depends(get_db),
):
    rec = db.execute(
        select(users_table).where(users_table.c.username == current_user.username)
    ).mappings().first()
    if not rec:
        raise HTTPException(status_code=404, detail="User not found")
    want_plain = as_bool("plain", plain_str, default=False) or False
    if want_plain and not _caller_is_admin(db, current_user.username):
        raise HTTPException(status_code=403, detail="Admin privileges required for plain export")
    payload = _build_api_for_user(dict(rec), request)
    final = _encrypt_payload_if_needed(payload, do_encrypt=not want_plain)
    ts = datetime.utcnow().strftime("%Y%m%d")
    filename = f"api_{current_user.username}_{ts}.json"
    return JSONResponse(
        content=final,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
@app.get(
    "/users/{username}/credentials/api.json",
    tags=["Users"],
    summary="(Admin) Download API credentials for a user",
    response_description="API credentials JSON (download)",
    responses={
        200: {
            "description": "JSON file (download)",
            "content": {"application/json": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
def download_user_api_credentials(
    username: str = Path(..., description="Target username"),
    plain_str: Optional[str] = Query("", alias="plain", description="If true, return plaintext"),
    request: Request = None,
    _admin: User = Security(get_current_user, scopes=["admin"]),
    db: Session = Depends(get_db),
):
    rec = db.execute(
        select(users_table).where(users_table.c.username == username)
    ).mappings().first()
    if not rec:
        raise HTTPException(status_code=404, detail="User not found")
    want_plain = as_bool("plain", plain_str, default=False) or False
    payload = _build_api_for_user(dict(rec), request)
    final = _encrypt_payload_if_needed(payload, do_encrypt=not want_plain)
    ts = datetime.utcnow().strftime("%Y%m%d")
    filename = f"api_{username}_{ts}.json"
    return JSONResponse(
        content=final,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
# ------------------------------------------------------------------------------------------------
# CRUD: Items — canonical LIST, SEARCH, and standard CRUD
# ------------------------------------------------------------------------------------------------
@app.get("/items", response_model=List[Item], tags=["Items"], summary="List items")
def list_items(
    current_user: User = Security(get_current_user, scopes=["items:read"]),
    db: Session = Depends(get_db),
    # Paging & ordering only; filtering is for /items/search
    limit_str: Optional[str] = Query("", example="100"),
    offset_str: Optional[str] = Query("", example="0"),
    order_by: Optional[str] = Query("", description='e.g. "id:asc" or "name:desc"'),
):
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    q = select(items_table)
    q, _ = apply_ordering(q, items_table, order_by, default_col="id")
    q = q.offset(offset).limit(limit)
    rows = db.execute(q).mappings().all()
    return [to_item(dict(r)) for r in rows]
@app.get("/items/{item_id}", response_model=Item, tags=["Items"])
def get_item(
    item_id: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:read"]),
    db: Session = Depends(get_db),
):
    item_id_val = as_int("item_id", item_id, required=True)
    row = db.execute(
        select(items_table).where(items_table.c.id == item_id_val)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")
    return to_item(dict(row))
@app.post("/items", response_model=Item, status_code=201, tags=["Items"])
def create_item(
    id_str: str = Form(..., example=""),
    name: str = Form(..., example="GPS"),
    description: str = Form(..., example=""),
    price_str: str = Form(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    id_ = as_int("id", id_str, required=True)
    price = as_float("price", price_str, required=True)
    exists = db.execute(
        select(items_table.c.id).where(items_table.c.id == id_)
    ).scalar()
    if exists is not None:
        raise HTTPException(status_code=409, detail=f"Item with id {id_} already exists")
    db.execute(insert(items_table).values(id=id_, name=name.strip(), description=description.strip(), price=price))
    db.commit()
    row = db.execute(
        select(items_table).where(items_table.c.id == id_)
    ).mappings().first()
    return to_item(dict(row))
@app.put("/items/{item_id}", response_model=Item, tags=["Items"])
def update_item(
    item_id: str = Path(..., example=""),
    name: str = Form(..., example="GPS"),
    description: str = Form(..., example=""),
    price_str: str = Form(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    item_id_val = as_int("item_id", item_id, required=True)
    price = as_float("price", price_str, required=True)
    values = {"name": name.strip(), "description": description.strip(), "price": price}
    res = db.execute(
        update(items_table).where(items_table.c.id == item_id_val).values(**values)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    db.commit()
    row = db.execute(
        select(items_table).where(items_table.c.id == item_id_val)
    ).mappings().first()
    return to_item(dict(row))
@app.delete("/items/{item_id}", tags=["Items"])
def delete_item(
    item_id: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["items:write"]),
    db: Session = Depends(get_db),
):
    item_id_val = as_int("item_id", item_id, required=True)
    res = db.execute(delete(items_table).where(items_table.c.id == item_id_val))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    db.commit()
    return {"message": "Item deleted"}
@app.get("/items/search", response_model=List[Item], tags=["Items"], summary="Search items")
def search_items(
    current_user: User = Security(get_current_user, scopes=["items:read"]),
    db: Session = Depends(get_db),
    id_str: Optional[str] = Query("", alias="ID", example="1"),
    name: Optional[str] = Query("", alias="NAME", example="MOUSE"),
    partial_str: Optional[str] = Query("", description="Use partial matches (ILIKE) when true"),
    limit_str: Optional[str] = Query("", example="100"),
    offset_str: Optional[str] = Query("", example="0"),
    order_by: Optional[str] = Query("", description='e.g. "name:asc" or "id:desc"'),
):
    partial = as_bool("partial", partial_str, default=True)
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    id_val = as_int("id", id_str)
    q = select(items_table)
    if id_val is not None:
        q = q.where(items_table.c.id == id_val)
    if not _is_blank(name):
        q = q.where(items_table.c.name.ilike(f"%{name}%") if partial else (items_table.c.name == name))
    q, _ = apply_ordering(q, items_table, order_by, default_col="id")
    q = q.offset(offset).limit(limit)
    rows = db.execute(q).mappings().all()
    return [to_item(dict(r)) for r in rows]
# ------------------------------------------------------------------------------------------------
# Extras — unified LIST and SEARCH; standard CRUD (removed /extras/list)
# ------------------------------------------------------------------------------------------------
@app.get("/extras", response_model=List[Extra], tags=["Extras"], summary="List extras")
def list_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    limit_str: Optional[str] = Query("", example="100"),
    offset_str: Optional[str] = Query("", example="0"),
    order_by: Optional[str] = Query("", description='e.g. "extras_code:asc"'),
):
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    query = select(extras_table)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="extras_code")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]
@app.get("/extras/{code}", response_model=Extra, tags=["Extras"])
def get_extra(
    code: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
):
    code = code.strip()
    row = db.execute(
        select(extras_table).where(extras_table.c.extras_code == code)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Extra not found")
    return to_extra(dict(row))
@app.post("/extras", response_model=Extra, status_code=201, tags=["Extras"])
def create_extra(
    extras_code: Optional[str] = Form("", example="001"),
    name: Optional[str] = Form("", example="GPS"),
    english_name: Optional[str] = Form("", example="GPS UNIT"),
    extra_unit_str: Optional[str] = Form("", example="1"),
    extra_group_str: Optional[str] = Form("", example="10"),
    vat_str: Optional[str] = Form("", example="15"),
    vat_code: Optional[str] = Form("", example="VAT15"),
    inventory: Optional[str] = Form("", example="Y"),
    gl_code: Optional[str] = Form("", example="5000-000"),
    gl_code_sl: Optional[str] = Form("", example="5000-001"),
    international_code: Optional[str] = Form("", example="INT12345"),
    allow_in_cs_str: Optional[str] = Form("", example="1"),
    allow_in_web_str: Optional[str] = Form("", example="1"),
    allow_in_client_str: Optional[str] = Form("", example="1"),
    allow_in_portal_str: Optional[str] = Form("", example="1"),
    ext_extra_for: Optional[str] = Form("", example="E"),
    calculate_vat: Optional[str] = Form("", example="Y"),
    inventory_by_subextra_str: Optional[str] = Form("", example="0"),
    sub_extra_lastno_str: Optional[str] = Form("", example="0"),
    flat_amount_yn: Optional[str] = Form("", example="N"),
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    extras_code = as_str_or_none(extras_code)
    name = as_str_or_none(name)
    if not extras_code and not name:
        raise HTTPException(status_code=422, detail="Either extras_code or name must be provided")
    if extras_code:
        exists = db.execute(
            select(extras_table.c.extras_code).where(extras_table.c.extras_code == extras_code)
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"Extra with code {extras_code} already exists")
    payload = {
        "extras_code": extras_code,
        "name": name,
        "english_name": as_str_or_none(english_name),
        "extra_unit": as_int("extra_unit", extra_unit_str),
        "extra_group": as_int("extra_group", extra_group_str),
        "vat": as_float("vat", vat_str),
        "vat_code": as_str_or_none(vat_code),
        "inventory": as_str_or_none(inventory),
        "gl_code": as_str_or_none(gl_code),
        "gl_code_sl": as_str_or_none(gl_code_sl),
        "international_code": as_str_or_none(international_code),
        "allow_in_cs": as_int("allow_in_cs", allow_in_cs_str),
        "allow_in_web": as_int("allow_in_web", allow_in_web_str),
        "allow_in_client": as_int("allow_in_client", allow_in_client_str),
        "allow_in_portal": as_int("allow_in_portal", allow_in_portal_str),
        "ext_extra_for": as_str_or_none(ext_extra_for),
        "calculate_vat": as_str_or_none(calculate_vat),
        "inventory_by_subextra": as_int("inventory_by_subextra", inventory_by_subextra_str),
        "sub_extra_lastno": as_int("sub_extra_lastno", sub_extra_lastno_str),
        "flat_amount_yn": as_str_or_none(flat_amount_yn),
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    payload = _strip_str_values(payload)
    db.execute(insert(extras_table).values(**payload))
    db.commit()
    row = None
    if extras_code:
        row = db.execute(
            select(extras_table).where(extras_table.c.extras_code == extras_code)
        ).mappings().first()
    return to_extra(dict(row)) if row else Extra(**payload)
@app.put("/extras/{code}", response_model=Extra, tags=["Extras"])
def update_extra(
    code: str = Path(..., example=""),
    name: Optional[str] = Form("", example="GPS"),
    english_name: Optional[str] = Form("", example="GPS UNIT"),
    extra_unit_str: Optional[str] = Form("", example="1"),
    extra_group_str: Optional[str] = Form("", example="10"),
    vat_str: Optional[str] = Form("", example="15"),
    vat_code: Optional[str] = Form("", example="VAT15"),
    inventory: Optional[str] = Form("", example="Y"),
    gl_code: Optional[str] = Form("", example="5000-000"),
    gl_code_sl: Optional[str] = Form("", example="5000-001"),
    international_code: Optional[str] = Form("", example="INT12345"),
    allow_in_cs_str: Optional[str] = Form("", example="1"),
    allow_in_web_str: Optional[str] = Form("", example="1"),
    allow_in_client_str: Optional[str] = Form("", example="1"),
    allow_in_portal_str: Optional[str] = Form("", example="1"),
    ext_extra_for: Optional[str] = Form("", example="E"),
    calculate_vat: Optional[str] = Form("", example="Y"),
    inventory_by_subextra_str: Optional[str] = Form("", example="0"),
    sub_extra_lastno_str: Optional[str] = Form("", example="0"),
    flat_amount_yn: Optional[str] = Form("", example="N"),
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    code = code.strip()
    vals = {
        "name": as_str_or_none(name),
        "english_name": as_str_or_none(english_name),
        "extra_unit": as_int("extra_unit", extra_unit_str),
        "extra_group": as_int("extra_group", extra_group_str),
        "vat": as_float("vat", vat_str),
        "vat_code": as_str_or_none(vat_code),
        "inventory": as_str_or_none(inventory),
        "gl_code": as_str_or_none(gl_code),
        "gl_code_sl": as_str_or_none(gl_code_sl),
        "international_code": as_str_or_none(international_code),
        "allow_in_cs": as_int("allow_in_cs", allow_in_cs_str),
        "allow_in_web": as_int("allow_in_web", allow_in_web_str),
        "allow_in_client": as_int("allow_in_client", allow_in_client_str),
        "allow_in_portal": as_int("allow_in_portal", allow_in_portal_str),
        "ext_extra_for": as_str_or_none(ext_extra_for),
        "calculate_vat": as_str_or_none(calculate_vat),
        "inventory_by_subextra": as_int("inventory_by_subextra", inventory_by_subextra_str),
        "sub_extra_lastno": as_int("sub_extra_lastno", sub_extra_lastno_str),
        "flat_amount_yn": as_str_or_none(flat_amount_yn),
    }
    vals = {k: v for k, v in vals.items() if v is not None}
    vals = _strip_str_values(vals)
    if not vals:
        raise HTTPException(status_code=422, detail="No fields to update")
    res = db.execute(
        update(extras_table)
        .where(extras_table.c.extras_code == code)
        .values(**vals)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")
    db.commit()
    row = db.execute(
        select(extras_table).where(extras_table.c.extras_code == code)
    ).mappings().first()
    return to_extra(dict(row))
@app.delete("/extras/{code}", tags=["Extras"])
def delete_extra(
    code: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["extras:write"]),
    db: Session = Depends(get_db),
):
    code = code.strip()
    res = db.execute(delete(extras_table).where(extras_table.c.extras_code == code))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Extra not found")
    db.commit()
    return {"message": "Extra deleted"}
@app.get("/extras/search", response_model=List[Extra], tags=["Extras"], summary="Search extras")
def search_extras(
    current_user: User = Security(get_current_user, scopes=["extras:read"]),
    db: Session = Depends(get_db),
    code: Optional[str] = Query("", alias="EXTRAS_CODE", example=""),
    name: Optional[str] = Query("", alias="NAME", example=""),
    group_str: Optional[str] = Query("", alias="EXTRA_GROUP", example=""),
    inventory: Optional[str] = Query("", alias="INVENTORY", example=""),
    partial_str: Optional[str] = Query("", description="Use partial matches (ILIKE)", example=""),
    limit_str: Optional[str] = Query("", example="100"),
    offset_str: Optional[str] = Query("", example="0"),
    order_by: Optional[str] = Query("", description='e.g. "name:asc"', example=""),
):
    partial = as_bool("partial", partial_str, default=True)
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    group_val = as_int("EXTRA_GROUP", group_str)
    query = select(extras_table)
    if not _is_blank(code):
        query = query.where(extras_table.c.extras_code.ilike(f"%{code}%") if partial else (extras_table.c.extras_code == code))
    if not _is_blank(name):
        query = query.where(extras_table.c.name.ilike(f"%{name}%") if partial else (extras_table.c.name == name))
    if group_val is not None:
        query = query.where(extras_table.c.extra_group == group_val)
    if not _is_blank(inventory):
        query = query.where(extras_table.c.inventory == inventory)
    query, _ = apply_ordering(query, extras_table, order_by, default_col="extras_code")
    query = query.offset(offset).limit(limit)
    rows = db.execute(query).mappings().all()
    return [to_extra(dict(r)) for r in rows]
# ------------------------------------------------------------------------------------------------
# CAR_CONTROL — consistent tag "Car Control"; LIST, SEARCH, CRUD (+ DELETE added)
# ------------------------------------------------------------------------------------------------
@app.get("/car_control", response_model=List[CarControl], tags=["Car Control"], summary="List car control rows")
def list_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    limit_str: Optional[str] = Query("", example="100"),
    offset_str: Optional[str] = Query("", example="0"),
    order_by: Optional[str] = Query("", description='e.g. "unit_no:asc"'),
):
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    q = select(car_control_table)
    q, _ = apply_ordering(q, car_control_table, order_by, default_col="unit_no")
    q = q.offset(offset).limit(limit)
    rows = db.execute(q).mappings().all()
    return [to_car_control(dict(r)) for r in rows]
@app.get("/car_control/{unit_no}", response_model=CarControl, tags=["Car Control"])
def get_car_control_one(
    unit_no: str = Path(..., example=""),
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
):
    unit_no = unit_no.strip()
    row = db.execute(
        select(car_control_table).where(car_control_table.c.unit_no == unit_no)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Car control row not found")
    return to_car_control(dict(row))
@app.post("/car_control", response_model=CarControl, status_code=201, tags=["Car Control"])
def create_car_control(
    unit_no: Optional[str] = Form("", example="100100000"),
    license_no: Optional[str] = Form("", example="6929HJD"),
    company_code_str: Optional[str] = Form("", example="1"),
    fleet_assignment: Optional[str] = Form("", example="B"),
    f_group: Optional[str] = Form("", example="FFAR"),
    car_make_str: Optional[str] = Form("", example="10"),
    model_str: Optional[str] = Form("", example="7"),
    color: Optional[str] = Form("", example="RED"),
    car_status_str: Optional[str] = Form("", example="7"),
    owner_country: Optional[str] = Form("", example="KSA"),
    check_out_date: Optional[str] = Form("", example="20251001"),
    check_out_time_str: Optional[str] = Form("", example="48480"),
    check_out_branach_str: Optional[str] = Form("", example="1"),
    check_in_date: Optional[str] = Form("", example="20251001"),
    check_in_time_str: Optional[str] = Form("", example="48540"),
    check_in_branach_str: Optional[str] = Form("", example="1"),
    branach_str: Optional[str] = Form("", example="1"),
    country: Optional[str] = Form("", example="KSA"),
    current_odometer_str: Optional[str] = Form("", example="100"),
    out_of_service_reas_str: Optional[str] = Form("", example="0"),
    vehicle_type: Optional[str] = Form("", example="VT"),
    parking_lot_code_str: Optional[str] = Form("", example="1"),
    parking_space_str: Optional[str] = Form("", example="1"),
    sale_cycle_str: Optional[str] = Form("", example="0"),
    last_document_type: Optional[str] = Form("", example="Y"),
    last_document_no_str: Optional[str] = Form("", example="1"),
    last_suv_agreement_str: Optional[str] = Form("", example="1"),
    odometer_after_min_str: Optional[str] = Form("", example="0"),
    reserved_to: Optional[str] = Form("", example="RSV000000012"),
    garage_str: Optional[str] = Form("", example="0"),
    smoke: Optional[str] = Form("", example="N"),
    telephone: Optional[str] = Form("", example="0555555555"),
    taxilimo_chauffeur: Optional[str] = Form("", example="NA"),
    prechecked_in_place: Optional[str] = Form("", example="Yard A"),
    fleet_sub_assignment_str: Optional[str] = Form("", example="0"),
    deposit_note_str: Optional[str] = Form("", example="0"),
    europcar_company: Optional[str] = Form("", example="N"),
    petrol_level_str: Optional[str] = Form("", example="0"),
    transaction_user: Optional[str] = Form("", example="BUGZY"),
    transaction_date: Optional[str] = Form("", example="20251001"),
    transaction_time_str: Optional[str] = Form("", example="0"),
    mortgaged_to_str: Optional[str] = Form("", example="0"),
    crc_inter_agr_str: Optional[str] = Form("", example="0"),
    lease_document_str: Optional[str] = Form("", example="0"),
    lease_srno_str: Optional[str] = Form("", example="0"),
    lease_document_type: Optional[str] = Form("", example="L"),
    lease_last_agreement_str: Optional[str] = Form("", example="0"),
    lease_last_sub_agrno_str: Optional[str] = Form("", example="0"),
    lease_veh_type_str: Optional[str] = Form("", example="SEDAN"),
    crc_chauffeur: Optional[str] = Form("", example="NA"),
    location_str: Optional[str] = Form("", example="0"),
    sub_status_str: Optional[str] = Form("", example="0"),
    promotional_veh: Optional[str] = Form("", example="N"),
    mark_preready_stat: Optional[str] = Form("", example="N"),
    yard_no_str: Optional[str] = Form("", example="0"),
    awxx_last_update_date: Optional[str] = Form("", example="2025-10-02T07:00:00Z"),
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    payload = {
        "unit_no": as_str_or_none(unit_no),
        "license_no": as_str_or_none(license_no),
        "company_code": as_int("company_code", company_code_str),
        "fleet_assignment": as_str_or_none(fleet_assignment),
        "f_group": as_str_or_none(f_group),
        "car_make": as_int("car_make", car_make_str),
        "model": as_int("model", model_str),
        "color": as_str_or_none(color),
        "car_status": as_int("car_status", car_status_str),
        "owner_country": as_str_or_none(owner_country),
        "check_out_date": as_str_or_none(check_out_date),
        "check_out_time": as_int("check_out_time", check_out_time_str),
        "check_out_branach": as_int("check_out_branach", check_out_branach_str),
        "check_in_date": as_str_or_none(check_in_date),
        "check_in_time": as_int("check_in_time", check_in_time_str),
        "check_in_branach": as_int("check_in_branach", check_in_branach_str),
        "branach": as_int("branach", branach_str),
        "country": as_str_or_none(country),
        "current_odometer": as_int("current_odometer", current_odometer_str),
        "out_of_service_reas": as_int("out_of_service_reas", out_of_service_reas_str),
        "vehicle_type": as_str_or_none(vehicle_type),
        "parking_lot_code": as_int("parking_lot_code", parking_lot_code_str),
        "parking_space": as_int("parking_space", parking_space_str),
        "sale_cycle": as_int("sale_cycle", sale_cycle_str),
        "last_document_type": as_str_or_none(last_document_type),
        "last_document_no": as_float("last_document_no", last_document_no_str),
        "last_suv_agreement": as_int("last_suv_agreement", last_suv_agreement_str),
        "odometer_after_min": as_int("odometer_after_min", odometer_after_min_str),
        "reserved_to": as_str_or_none(reserved_to),
        "garage": as_int("garage", garage_str),
        "smoke": as_str_or_none(smoke),
        "telephone": as_str_or_none(telephone),
        "taxilimo_chauffeur": as_str_or_none(taxilimo_chauffeur),
        "prechecked_in_place": as_str_or_none(prechecked_in_place),
        "fleet_sub_assignment": as_int("fleet_sub_assignment", fleet_sub_assignment_str),
        "deposit_note": as_float("deposit_note", deposit_note_str),
        "europcar_company": as_str_or_none(europcar_company),
        "petrol_level": as_int("petrol_level", petrol_level_str),
        "transaction_user": as_str_or_none(transaction_user),
        "transaction_date": as_str_or_none(transaction_date),
        "transaction_time": as_int("transaction_time", transaction_time_str),
        "mortgaged_to": as_int("mortgaged_to", mortgaged_to_str),
        "crc_inter_agr": as_int("crc_inter_agr", crc_inter_agr_str),
        "lease_document": as_int("lease_document", lease_document_str),
        "lease_srno": as_int("lease_srno", lease_srno_str),
        "lease_document_type": as_str_or_none(lease_document_type),
        "lease_last_agreement": as_int("lease_last_agreement", lease_last_agreement_str),
        "lease_last_sub_agrno": as_int("lease_last_sub_agrno", lease_last_sub_agrno_str),
        "lease_veh_type": as_str_or_none(lease_veh_type_str),
        "crc_chauffeur": as_str_or_none(crc_chauffeur),
        "location": as_int("location", location_str),
        "sub_status": as_int("sub_status", sub_status_str),
        "promotional_veh": as_str_or_none(promotional_veh),
        "mark_preready_stat": as_str_or_none(mark_preready_stat),
        "yard_no": as_int("yard_no", yard_no_str),
        "awxx_last_update_date": awxx_last_update_date,  # pass-through if provided
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    if not payload:
        raise HTTPException(status_code=422, detail="Request body is empty")
    if "unit_no" in payload and payload["unit_no"]:
        exists = db.execute(
            select(car_control_table.c.unit_no).where(car_control_table.c.unit_no == payload["unit_no"])
        ).scalar()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"unit_no {payload['unit_no']} already exists")
    db.execute(insert(car_control_table).values(**payload))
    db.commit()
    if "unit_no" in payload:
        row = db.execute(
            select(car_control_table).where(car_control_table.c.unit_no == payload["unit_no"])
        ).mappings().first()
        if row:
            return to_car_control(dict(row))
    return to_car_control(payload)
@app.get("/car_control/search", response_model=List[CarControl], tags=["Car Control"], summary="Search car control")
def search_car_control(
    current_user: User = Security(get_current_user, scopes=["cars:read"]),
    db: Session = Depends(get_db),
    # --- Common filters (UPPER-CASE aliases visible in Swagger/UI) ---
    unit_no: Optional[str] = Query("", alias="UNIT_NO"),
    license_no: Optional[str] = Query("", alias="LICENSE_NO"),
    company_code_str: Optional[str] = Query("", alias="COMPANY_CODE"),
    fleet_assignment: Optional[str] = Query("", alias="FLEET_ASSIGNMENT"),
    f_group: Optional[str] = Query("", alias="F_GROUP"),
    car_make_str: Optional[str] = Query("", alias="CAR_MAKE"),
    model_str: Optional[str] = Query("", alias="MODEL"),
    color: Optional[str] = Query("", alias="COLOR"),
    car_status_str: Optional[str] = Query("", alias="CAR_STATUS"),
    branach_str: Optional[str] = Query("", alias="BRANACH"),
    current_odometer_str: Optional[str] = Query("", alias="CURRENT_ODOMETER"),
    vehicle_type: Optional[str] = Query("", alias="VEHICLE_TYPE"),
    sale_cycle_str: Optional[str] = Query("", alias="SALE_CYCLE"),
    fleet_sub_assignment_str: Optional[str] = Query("", alias="FLEET_SUB_ASSIGNMENT"),
    smoke: Optional[str] = Query("", alias="SMOKE"),
    garage_str: Optional[str] = Query("", alias="GARAGE"),
    petrol_level_str: Optional[str] = Query("", alias="PETROL_LEVEL"),
    location_str: Optional[str] = Query("", alias="LOCATION"),
    sub_status_str: Optional[str] = Query("", alias="SUB_STATUS"),
    lease_veh_type: Optional[str] = Query("", alias="LEASE_VEH_TYPE"),
    # --- Search behavior & paging ---
    partial_str: Optional[str] = Query("", description="Use partial matches (ILIKE) when true"),
    limit_str: Optional[str] = Query(""),
    offset_str: Optional[str] = Query(""),
    order_by: Optional[str] = Query("", description='e.g. "unit_no:asc" or "license_no:desc"'),
):
    # Parse flags / paging
    partial = as_bool("partial", partial_str, default=True)
    limit = as_int("limit", limit_str) or 100
    offset = as_int("offset", offset_str) or 0
    # Parse numerics
    company_code = as_int("company_code", company_code_str)
    car_make = as_int("car_make", car_make_str)
    model = as_int("model", model_str)
    car_status = as_int("car_status", car_status_str)
    branach = as_int("branach", branach_str)
    current_odometer = as_int("current_odometer", current_odometer_str)
    sale_cycle = as_int("sale_cycle", sale_cycle_str)
    fleet_sub_assignment = as_int("fleet_sub_assignment", fleet_sub_assignment_str)
    garage = as_int("garage", garage_str)
    petrol_level = as_int("petrol_level", petrol_level_str)
    location = as_int("location", location_str)
    sub_status = as_int("sub_status", sub_status_str)
    # Build query
    q = select(car_control_table)
    # Strings: partial/exact via like_or_equals; Numerics: exact equality
    if not _is_blank(unit_no):
        q = q.where(like_or_equals(car_control_table.c.unit_no, unit_no, partial))
    if not _is_blank(license_no):
        q = q.where(like_or_equals(car_control_table.c.license_no, license_no, partial))
    if company_code is not None:
        q = q.where(car_control_table.c.company_code == company_code)
    if not _is_blank(fleet_assignment):
        q = q.where(like_or_equals(car_control_table.c.fleet_assignment, fleet_assignment, partial))
    if not _is_blank(f_group):
        q = q.where(like_or_equals(car_control_table.c.f_group, f_group, partial))
    if car_make is not None:
        q = q.where(car_control_table.c.car_make == car_make)
    if model is not None:
        q = q.where(car_control_table.c.model == model)
    if not _is_blank(color):
        q = q.where(like_or_equals(car_control_table.c.color, color, partial))
    if car_status is not None:
        q = q.where(car_control_table.c.car_status == car_status)
    if branach is not None:
        q = q.where(car_control_table.c.branach == branach)
    if current_odometer is not None:
        q = q.where(car_control_table.c.current_odometer == current_odometer)
    if not _is_blank(vehicle_type):
        q = q.where(like_or_equals(car_control_table.c.vehicle_type, vehicle_type, partial))
    if sale_cycle is not None:
        q = q.where(car_control_table.c.sale_cycle == sale_cycle)
    if fleet_sub_assignment is not None:
        q = q.where(car_control_table.c.fleet_sub_assignment == fleet_sub_assignment)
    if not _is_blank(smoke):
        q = q.where(like_or_equals(car_control_table.c.smoke, smoke, partial))
    if garage is not None:
        q = q.where(car_control_table.c.garage == garage)
    if petrol_level is not None:
        q = q.where(car_control_table.c.petrol_level == petrol_level)
    if location is not None:
        q = q.where(car_control_table.c.location == location)
    if sub_status is not None:
        q = q.where(car_control_table.c.sub_status == sub_status)
    if not _is_blank(lease_veh_type):
        q = q.where(like_or_equals(car_control_table.c.lease_veh_type, lease_veh_type, partial))
    # Ordering + paging
    q, _ = apply_ordering(q, car_control_table, order_by, default_col="unit_no")
    q = q.offset(offset).limit(limit)
    rows = db.execute(q).mappings().all()
    return [to_car_control(dict(r)) for r in rows]
@app.put("/car_control/{unit_no}", response_model=CarControl, tags=["Car Control"])
def update_car_control(
    unit_no: str = Path(..., example=""),
    license_no: Optional[str] = Form("", example="6929HJD"),
    company_code_str: Optional[str] = Form("", example="1"),
    fleet_assignment: Optional[str] = Form("", example="B"),
    f_group: Optional[str] = Form("", example="FFAR"),
    car_make_str: Optional[str] = Form("", example="10"),
    model_str: Optional[str] = Form("", example="7"),
    color: Optional[str] = Form("", example="RED"),
    car_status_str: Optional[str] = Form("", example="7"),
    owner_country: Optional[str] = Form("", example="KSA"),
    check_out_date: Optional[str] = Form("", example="20251001"),
    check_out_time_str: Optional[str] = Form("", example="48480"),
    check_out_branach_str: Optional[str] = Form("", example="1"),
    check_in_date: Optional[str] = Form("", example="20251001"),
    check_in_time_str: Optional[str] = Form("", example="48540"),
    check_in_branach_str: Optional[str] = Form("", example="1"),
    branach_str: Optional[str] = Form("", example="1"),
    country: Optional[str] = Form("", example="KSA"),
    current_odometer_str: Optional[str] = Form("", example="100"),
    out_of_service_reas_str: Optional[str] = Form("", example="0"),
    vehicle_type: Optional[str] = Form("", example="VT"),
    parking_lot_code_str: Optional[str] = Form("", example="1"),
    parking_space_str: Optional[str] = Form("", example="1"),
    sale_cycle_str: Optional[str] = Form("", example="0"),
    last_document_type: Optional[str] = Form("", example="Y"),
    last_document_no_str: Optional[str] = Form("", example="1"),
    last_suv_agreement_str: Optional[str] = Form("", example="1"),
    odometer_after_min_str: Optional[str] = Form("", example="0"),
    reserved_to: Optional[str] = Form("", example="RSV000000012"),
    garage_str: Optional[str] = Form("", example="0"),
    smoke: Optional[str] = Form("", example="N"),
    telephone: Optional[str] = Form("", example="0555555555"),
    taxilimo_chauffeur: Optional[str] = Form("", example="NA"),
    prechecked_in_place: Optional[str] = Form("", example="Yard A"),
    fleet_sub_assignment_str: Optional[str] = Form("", example="0"),
    deposit_note_str: Optional[str] = Form("", example="0"),
    europcar_company: Optional[str] = Form("", example="N"),
    petrol_level_str: Optional[str] = Form("", example="0"),
    transaction_user: Optional[str] = Form("", example="BUGZY"),
    transaction_date: Optional[str] = Form("", example="20251001"),
    transaction_time_str: Optional[str] = Form("", example="0"),
    mortgaged_to_str: Optional[str] = Form("", example="0"),
    crc_inter_agr_str: Optional[str] = Form("", example="0"),
    lease_document_str: Optional[str] = Form("", example="0"),
    lease_srno_str: Optional[str] = Form("", example="0"),
    lease_document_type: Optional[str] = Form("", example="L"),
    lease_last_agreement_str: Optional[str] = Form("", example="0"),
    lease_last_sub_agrno_str: Optional[str] = Form("", example="0"),
    lease_veh_type_str: Optional[str] = Form("", example="SEDAN"),
    crc_chauffeur: Optional[str] = Form("", example="NA"),
    location_str: Optional[str] = Form("", example="0"),
    sub_status_str: Optional[str] = Form("", example="0"),
    promotional_veh: Optional[str] = Form("", example="N"),
    mark_preready_stat: Optional[str] = Form("", example="N"),
    yard_no_str: Optional[str] = Form("", example="0"),
    awxx_last_update_date: Optional[str] = Form("", example="2025-10-02T07:00:00Z"),
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    unit_no = unit_no.strip()
    payload = {
        "license_no": as_str_or_none(license_no),
        "company_code": as_int("company_code", company_code_str),
        "fleet_assignment": as_str_or_none(fleet_assignment),
        "f_group": as_str_or_none(f_group),
        "car_make": as_int("car_make", car_make_str),
        "model": as_int("model", model_str),
        "color": as_str_or_none(color),
        "car_status": as_int("car_status", car_status_str),
        "owner_country": as_str_or_none(owner_country),
        "check_out_date": as_str_or_none(check_out_date),
        "check_out_time": as_int("check_out_time", check_out_time_str),
        "check_out_branach": as_int("check_out_branach", check_out_branach_str),
        "check_in_date": as_str_or_none(check_in_date),
        "check_in_time": as_int("check_in_time", check_in_time_str),
        "check_in_branach": as_int("check_in_branach", check_in_branach_str),
        "branach": as_int("branach", branach_str),
        "country": as_str_or_none(country),
        "current_odometer": as_int("current_odometer", current_odometer_str),
        "out_of_service_reas": as_int("out_of_service_reas", out_of_service_reas_str),
        "vehicle_type": as_str_or_none(vehicle_type),
        "parking_lot_code": as_int("parking_lot_code", parking_lot_code_str),
        "parking_space": as_int("parking_space", parking_space_str),
        "sale_cycle": as_int("sale_cycle", sale_cycle_str),
        "last_document_type": as_str_or_none(last_document_type),
        "last_document_no": as_float("last_document_no", last_document_no_str),
        "last_suv_agreement": as_int("last_suv_agreement", last_suv_agreement_str),
        "odometer_after_min": as_int("odometer_after_min", odometer_after_min_str),
        "reserved_to": as_str_or_none(reserved_to),
        "garage": as_int("garage", garage_str),
        "smoke": as_str_or_none(smoke),
        "telephone": as_str_or_none(telephone),
        "taxilimo_chauffeur": as_str_or_none(taxilimo_chauffeur),
        "prechecked_in_place": as_str_or_none(prechecked_in_place),
        "fleet_sub_assignment": as_int("fleet_sub_assignment", fleet_sub_assignment_str),
        "deposit_note": as_float("deposit_note", deposit_note_str),
        "europcar_company": as_str_or_none(europcar_company),
        "petrol_level": as_int("petrol_level", petrol_level_str),
        "transaction_user": as_str_or_none(transaction_user),
        "transaction_date": as_str_or_none(transaction_date),
        "transaction_time": as_int("transaction_time", transaction_time_str),
        "mortgaged_to": as_int("mortgaged_to", mortgaged_to_str),
        "crc_inter_agr": as_int("crc_inter_agr", crc_inter_agr_str),
        "lease_document": as_int("lease_document", lease_document_str),
        "lease_srno": as_int("lease_srno", lease_srno_str),
        "lease_document_type": as_str_or_none(lease_document_type),
        "lease_last_agreement": as_int("lease_last_agreement", lease_last_agreement_str),
        "lease_last_sub_agrno": as_int("lease_last_sub_agrno", lease_last_sub_agrno_str),
        "lease_veh_type": as_str_or_none(lease_veh_type_str),
        "crc_chauffeur": as_str_or_none(crc_chauffeur),
        "location": as_int("location", location_str),
        "sub_status": as_int("sub_status", sub_status_str),
        "promotional_veh": as_str_or_none(promotional_veh),
        "mark_preready_stat": as_str_or_none(mark_preready_stat),
        "yard_no": as_int("yard_no", yard_no_str),
        "awxx_last_update_date": awxx_last_update_date,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    if not payload:
        raise HTTPException(status_code=422, detail="No fields to update")
    res = db.execute(
        update(car_control_table)
        .where(car_control_table.c.unit_no == unit_no)
        .values(**payload)
    )
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")
    db.commit()
    row = db.execute(
        select(car_control_table).where(car_control_table.c.unit_no == unit_no)
    ).mappings().first()
    return to_car_control(dict(row))
@app.delete("/car_control/{unit_no}", tags=["Car Control"], summary="Delete car control row")
def delete_car_control(
    unit_no: str = Path(..., example="100100000"),
    current_user: User = Security(get_current_user, scopes=["cars:write"]),
    db: Session = Depends(get_db),
):
    unit_no = unit_no.strip()
    res = db.execute(delete(car_control_table).where(car_control_table.c.unit_no == unit_no))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="Car control row not found")
    db.commit()
    return {"message": "Car control row deleted"}
# ------------------------------------------------------------------------------------------------
# Health Check (tagged to avoid "Default" section)
# ------------------------------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
# ------------------------------------------------------------------------------------------------
# Startup
# ------------------------------------------------------------------------------------------------
@app.on_event("startup")
def ensure_tables_and_seed_user():
    # Create missing tables if they don't exist
    metadata.create_all(engine)
    # Try to ensure columns exist when running on Postgres. For other dialects, skip these
    # ALTERs (metadata.create_all covers new deployments).
    try:
        if engine.dialect.name.startswith("postgres"):
            with engine.connect() as conn:
                # scopes column
                has_scopes_col = conn.execute(text(
                    """
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'scopes'
                    """
                )).first()
                if not has_scopes_col:
                    conn.execute(text("ALTER TABLE users ADD COLUMN scopes TEXT"))
                    conn.commit()
                # token_version column
                has_ver_col = conn.execute(text(
                    """
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'token_version'
                    """
                )).first()
                if not has_ver_col:
                    conn.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1"))
                    conn.commit()
                # per-user keys columns
                has_saak_col = conn.execute(text(
                    """
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'saak'
                    """
                )).first()
                if not has_saak_col:
                    conn.execute(text("ALTER TABLE users ADD COLUMN saak TEXT"))
                    conn.commit()
                has_sask_col = conn.execute(text(
                    """
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'sask'
                    """
                )).first()
                if not has_sask_col:
                    conn.execute(text("ALTER TABLE users ADD COLUMN sask TEXT"))
                    conn.commit()
    except Exception as _e:
        # Non-fatal; schema drift checks are best-effort
        pass
    seed = os.getenv("SEED_DEFAULT_USER", "true").lower() == "true"
    if not seed:
        return
    with SessionLocal() as db:
        existing = db.execute(
            select(users_table.c.username).where(users_table.c.username == "bugzy")
        )