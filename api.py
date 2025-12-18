import os, json, jwt, base64
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Config
JWT_SECRET = "KID_UAS_SECRET"
JWT_ALG = "HS256"
JWT_EXP_MIN = 60

DATA_DIR = "data"
USERS_FILE = f"{DATA_DIR}/users.json"
INBOX_FILE = f"{DATA_DIR}/inbox.json"
LOG_FILE = f"{DATA_DIR}/activity_log.json"

os.makedirs(DATA_DIR, exist_ok=True)
for f in [USERS_FILE, INBOX_FILE, LOG_FILE]:
    if not os.path.exists(f):
        with open(f, "w") as x:
            json.dump({} if f != LOG_FILE else [], x)

app = FastAPI(title="Security Service Kelompok 2", version="1.0")
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
def load(p): return json.load(open(p))
def save(p, d): json.dump(d, open(p,"w"), indent=2)

def create_token(username):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MIN)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])["sub"]
    except:
        raise HTTPException(401, "Invalid / expired token")

# Audit Log
@app.middleware("http")
async def logger(req: Request, call_next):
    user = "anonymous"
    auth = req.headers.get("authorization")
    if auth and auth.lower().startswith("bearer"):
        try:
            user = jwt.decode(auth.split()[1], JWT_SECRET, algorithms=[JWT_ALG])["sub"]
        except:
            user = "invalid-token"

    res = await call_next(req)
    logs = load(LOG_FILE)
    logs.append({
        "time": datetime.utcnow().isoformat(),
        "path": req.url.path,
        "method": req.method,
        "user": user,
        "status": res.status_code
    })
    save(LOG_FILE, logs)
    return res

# Endpoint
@app.get("/health")
def health():
    return {"status": "OK", "time": datetime.utcnow().isoformat()}

@app.post("/register")
async def register(username: str = Form(...), pubkey: UploadFile = File(...)):
    users = load(USERS_FILE)
    if username in users:
        raise HTTPException(400, "User exists")

    key_bytes = await pubkey.read()
    key = serialization.load_pem_public_key(key_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise HTTPException(400, "Invalid Ed25519 key")

    users[username] = {"pubkey": key_bytes.decode()}
    save(USERS_FILE, users)
    return {"message": "Registered"}

@app.post("/token")
async def login(username: str = Form(...)):
    users = load(USERS_FILE)
    if username not in users:
        raise HTTPException(401, "User not registered")
    return {"access_token": create_token(username)}

@app.post("/verify-text")
async def verify_text(
    sender: str = Form(...),
    message: str = Form(...),
    signature_hex: str = Form(...),
    user: str = Depends(get_current_user)
):
    users = load(USERS_FILE)

    if sender not in users:
        raise HTTPException(404, "Sender not registered")

    try:
        signature = bytes.fromhex(signature_hex)
        pubkey = serialization.load_pem_public_key(
            users[sender]["pubkey"].encode()
        )

        pubkey.verify(signature, message.encode())

        return {
            "status": "VALID",
            "signed_by": sender,
            "verified_by": user
        }

    except InvalidSignature:
        raise HTTPException(400, "INVALID SIGNATURE")

    except ValueError:
        raise HTTPException(400, "Signature is not valid hex")


@app.post("/verify-pdf")
async def verify_pdf(
    sender: str = Form(...),
    signature_hex: str = Form(...),
    pdf: UploadFile = File(...),
    user: str = Depends(get_current_user)
):
    users = load(USERS_FILE)

    if sender not in users:
        raise HTTPException(404, "Sender not registered")

    try:
        pdf_bytes = await pdf.read()
        signature = bytes.fromhex(signature_hex)

        pubkey = serialization.load_pem_public_key(
            users[sender]["pubkey"].encode()
        )

        pubkey.verify(signature, pdf_bytes)

        return {
            "status": "VALID",
            "signed_by": sender,
            "verified_by": user
        }

    except InvalidSignature:
        raise HTTPException(400, "INVALID SIGNATURE")

    except ValueError:
        raise HTTPException(400, "Signature is not valid hex")

@app.post("/relay-text")
async def relay_text(
    to: str = Form(...),
    message: str = Form(...),
    signature_hex: str = Form(...),
    sender: str = Depends(get_current_user)
):
    users = load(USERS_FILE)
    pubkey = serialization.load_pem_public_key(users[sender]["pubkey"].encode())
    pubkey.verify(bytes.fromhex(signature_hex), message.encode())

    inbox = load(INBOX_FILE)
    inbox.setdefault(to, []).append({
        "type": "text",
        "from": sender,
        "message": message,
        "signature": signature_hex,
        "time": datetime.utcnow().isoformat()
    })
    save(INBOX_FILE, inbox)
    return {"message": "Text relayed"}

@app.post("/relay-pdf")
async def relay_pdf(
    to: str = Form(...),
    signature_hex: str = Form(...),
    pdf: UploadFile = File(...),
    sender: str = Depends(get_current_user)
):
    users = load(USERS_FILE)
    pdf_bytes = await pdf.read()
    pubkey = serialization.load_pem_public_key(users[sender]["pubkey"].encode())
    pubkey.verify(bytes.fromhex(signature_hex), pdf_bytes)

    inbox = load(INBOX_FILE)
    inbox.setdefault(to, []).append({
        "type": "pdf",
        "from": sender,
        "filename": pdf.filename,
        "pdf_base64": base64.b64encode(pdf_bytes).decode(),
        "signature": signature_hex,
        "time": datetime.utcnow().isoformat()
    })
    save(INBOX_FILE, inbox)
    return {"message": "PDF relayed"}

@app.get("/inbox")
async def inbox(user: str = Depends(get_current_user)):
    return load(INBOX_FILE).get(user, [])