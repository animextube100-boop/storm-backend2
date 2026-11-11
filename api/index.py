import os, hmac, hashlib, json, time
from urllib.parse import parse_qsl
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="STORM Payment Verification API")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
TONAPI_KEY = os.getenv("TONAPI_KEY", "")
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
PAYMENT_WALLET = os.getenv("PAYMENT_WALLET", "UQCo0-D4DWT4Q99BJ35ONA7wduh_qtNwwpni55UyMhsFcY-x")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN else [],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

PAYMENTS = {
    "verification": 500_000_000,
    "basic": 1_000_000_000,
    "advanced": 2_500_000_000,
    "pro": 5_000_000_000,
    "ultra": 10_000_000_000,
    "legendary": 25_000_000_000,
}

class VerifyRequest(BaseModel):
    init_data: str = Field(min_length=1)
    tx_hash: str = Field(min_length=8, max_length=256)
    payment_type: str

def validate_init_data(raw):
    if not BOT_TOKEN:
        raise HTTPException(500, "BOT_TOKEN is not configured")
    try:
        values = dict(parse_qsl(raw, keep_blank_values=True))
        received_hash = values.pop("hash")
        auth_date = int(values.get("auth_date", "0"))
    except Exception:
        raise HTTPException(401, "Invalid Telegram initData")
    if auth_date <= 0 or time.time() - auth_date > 86400:
        raise HTTPException(401, "Telegram initData expired")
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, received_hash):
        raise HTTPException(401, "Telegram initData signature is invalid")
    try:
        return str(json.loads(values["user"])["id"])
    except Exception:
        raise HTTPException(401, "Telegram user data missing")

def supabase_headers():
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise HTTPException(500, "Supabase environment variables are missing")
    return {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

@app.get("/health")
async def health():
    return {"ok": True, "service": "storm-payment-verification"}

@app.post("/verify-payment")
async def verify_payment(body: VerifyRequest):
    if body.payment_type not in PAYMENTS:
        raise HTTPException(400, "Unknown payment type")
    user_id = validate_init_data(body.init_data)
    tx_hash = body.tx_hash.strip()
    if "://" in tx_hash:
        tx_hash = tx_hash.rstrip("/").split("/")[-1].split("?")[0]
    if not TONAPI_KEY:
        raise HTTPException(500, "TONAPI_KEY is not configured")

    headers = {"Authorization": f"Bearer {TONAPI_KEY}"}
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(
            f"https://tonapi.io/v2/blockchain/transactions/{tx_hash}",
            headers=headers
        )
    if response.status_code == 404:
        raise HTTPException(400, "Transaction not found")
    if response.status_code != 200:
        raise HTTPException(502, "TON transaction lookup failed")
    tx = response.json()

    if tx.get("aborted") is True or tx.get("success") is False:
        raise HTTPException(400, "Transaction failed or was aborted")
    in_msg = tx.get("in_msg") or {}
    if not in_msg:
        raise HTTPException(400, "No incoming payment message found")

    destination = in_msg.get("destination") or {}
    dest = destination.get("address") if isinstance(destination, dict) else destination
    if not dest or dest != PAYMENT_WALLET:
        raise HTTPException(400, "Payment destination does not match STORM wallet")

    try:
        paid_nano = int(in_msg.get("value"))
    except Exception:
        raise HTTPException(400, "Could not read incoming TON amount")
    expected_nano = PAYMENTS[body.payment_type]
    if paid_nano != expected_nano:
        raise HTTPException(400, "Payment amount does not match selected payment type")

    source = in_msg.get("source") or {}
    sender = source.get("address") if isinstance(source, dict) else source
    record = {
        "tx_hash": tx_hash,
        "telegram_user_id": user_id,
        "payment_type": body.payment_type,
        "amount_nano": paid_nano,
        "sender_address": sender,
        "destination_address": dest,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        saved = await client.post(
            f"{SUPABASE_URL}/rest/v1/payment_claims",
            headers=supabase_headers(),
            json=record
        )
    if saved.status_code == 409:
        raise HTTPException(409, "This transaction hash has already been claimed")
    if saved.status_code not in (200, 201):
        raise HTTPException(502, "Could not save payment claim")

    return {"ok": True, "verified": True, "payment_type": body.payment_type,
            "amount_nano": paid_nano, "telegram_user_id": user_id,
            "note": "Claim recorded only; miner activation/token crediting is not implemented."}
