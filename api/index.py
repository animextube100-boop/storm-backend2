
import os
import re
import hmac
import hashlib
import json
import time
import base64
import uuid
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("storm-payments")
app = FastAPI(title="STORM Payment Verification API")

# ------------------------------------------------------------- CONFIG ---

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "").rstrip("/")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
TONAPI_KEY = os.getenv("TONAPI_KEY", "")
TONAPI_BASE_URL = os.getenv(
    "TONAPI_BASE_URL", "https://tonapi.io"
).rstrip("/")
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
PAYMENT_WALLET = os.getenv("PAYMENT_WALLET", "").strip()

PAYMENT_WINDOW_SECONDS = 240
TONAPI_TIMEOUT = 8
SUPABASE_TIMEOUT = 5

PAYMENTS = {
    "verification": 500_000_000,
    "basic": 1_000_000_000,
    "advanced": 2_500_000_000,
    "pro": 5_000_000_000,
    "ultra": 10_000_000_000,
    "legendary": 25_000_000_000,
}

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
B64URL = re.compile(r"^[A-Za-z0-9_-]{43}={0,1}$")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN else [],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ------------------------------------------------------- ERROR HANDLING ---

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        {"ok": False, "error": exc.detail, "detail": exc.detail},
        status_code=exc.status_code,
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    fields = [
        {
            "loc": [str(x) for x in e.get("loc", [])],
            "msg": e.get("msg", ""),
        }
        for e in exc.errors()
    ]
    return JSONResponse(
        {
            "ok": False,
            "error": "Invalid request body",
            "detail": "Invalid request body",
            "fields": fields,
        },
        status_code=422,
    )


# ------------------------------------------------------------- MODELS ---

class CreatePaymentRequest(BaseModel):
    init_data: str = Field(min_length=1, max_length=8192)
    payment_type: str = Field(min_length=1, max_length=32)


class VerifyRequest(BaseModel):
    init_data: str = Field(min_length=1, max_length=8192)
    tx_hash: str = Field(min_length=8, max_length=512)
    payment_request_id: uuid.UUID


# ---------------------------------------------------------- TELEGRAM ---

def validate_init_data(raw: str) -> str:
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

    check_string = "\n".join(
        f"{k}={v}" for k, v in sorted(values.items())
    )

    secret = hmac.new(
        b"WebAppData",
        BOT_TOKEN.encode(),
        hashlib.sha256,
    ).digest()

    expected = hmac.new(
        secret,
        check_string.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, received_hash):
        raise HTTPException(401, "Telegram initData signature is invalid")

    try:
        return str(int(json.loads(values["user"])["id"]))
    except Exception:
        raise HTTPException(401, "Telegram user data missing")


# ----------------------------------------------------------- SUPABASE ---

def _sb_headers(prefer):
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise HTTPException(
            500, "Supabase environment variables are missing"
        )

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    if prefer:
        headers["Prefer"] = prefer

    return headers


async def sb(method, path, *, params=None, body=None, prefer="return=representation"):
    headers = _sb_headers(prefer)

    try:
        async with httpx.AsyncClient(timeout=SUPABASE_TIMEOUT) as client:
            return await client.request(
                method,
                f"{SUPABASE_URL}/rest/v1/{path}",
                headers=headers,
                params=params,
                json=body,
            )
    except httpx.HTTPError:
        raise HTTPException(
            503, "Database temporarily unavailable, try again"
        )


def utcnow():
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ts(s: str) -> datetime:
    s = s.strip().replace("Z", "+00:00").replace(" ", "T")
    m = re.match(r"^(.*?)(\.\d+)?([+-]\d\d)(?::?(\d\d))?$", s)

    if not m:
        raise ValueError(f"bad timestamp {s!r}")

    base, frac, tzh, tzm = m.groups()
    frac = (frac or ".0")[:7].ljust(7, "0")

    return datetime.fromisoformat(
        f"{base}{frac}{tzh}:{tzm or '00'}"
    ).astimezone(timezone.utc)


async def get_payment_request(request_id: str):
    r = await sb(
        "GET",
        "payment_requests",
        params={
            "id": f"eq.{request_id}",
            "select": "*",
            "limit": "1",
        },
    )

    if r.status_code != 200:
        raise HTTPException(502, "Could not read payment request")

    rows = r.json()
    return rows[0] if rows else None


async def set_request_status(request_id: str, new_status: str):
    try:
        await sb(
            "PATCH",
            "payment_requests",
            params={
                "id": f"eq.{request_id}",
                "status": "eq.pending",
            },
            body={"status": new_status},
            prefer="return=minimal",
        )
    except HTTPException:
        pass


# --------------------------------------------------------- TON ADDRESS ---

def _crc16_xmodem(data: bytes) -> int:
    crc = 0

    for b in data:
        crc ^= b << 8

        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021)
                if crc & 0x8000
                else (crc << 1)
            )
            crc &= 0xFFFF

    return crc


def parse_ton_address(addr):
    if not isinstance(addr, str):
        raise ValueError("address is not a string")

    addr = addr.strip()

    if ":" in addr:
        wc, h = addr.split(":", 1)

        if not HEX64.match(h):
            raise ValueError("bad raw address")

        return int(wc), bytes.fromhex(h)

    if len(addr) != 48:
        raise ValueError("bad friendly address length")

    raw = base64.urlsafe_b64decode(
        addr.replace("+", "-").replace("/", "_")
    )

    if (
        len(raw) != 36
        or _crc16_xmodem(raw[:34]) != int.from_bytes(raw[34:], "big")
    ):
        raise ValueError("bad friendly address checksum")

    if (raw[0] & 0x7F) not in (0x11, 0x51):
        raise ValueError("bad friendly address tag")

    return (
        int.from_bytes(raw[1:2], "big", signed=True),
        raw[2:34],
    )


def same_address(a, b) -> bool:
    try:
        return parse_ton_address(a) == parse_ton_address(b)
    except Exception:
        return False


def addr_str(field):
    if isinstance(field, dict):
        return field.get("address")

    return field if isinstance(field, str) else None


# --------------------------------------------------------- TONAPI TRACE ---

async def fetch_trace(tx_hash: str) -> dict:
    if not TONAPI_KEY:
        raise HTTPException(500, "TONAPI_KEY is not configured")

    try:
        async with httpx.AsyncClient(timeout=TONAPI_TIMEOUT) as client:
            r = await client.get(
                f"{TONAPI_BASE_URL}/v2/traces/{tx_hash}",
                headers={"Authorization": f"Bearer {TONAPI_KEY}"},
            )
    except httpx.HTTPError:
        raise HTTPException(
            503, "TON API unreachable, try again shortly"
        )

    if r.status_code == 404:
        raise HTTPException(
            404, "Transaction trace not found yet. Retry in a few seconds."
        )

    if r.status_code == 429:
        raise HTTPException(
            503,
            "TON API rate limit reached, retry shortly",
            headers={"Retry-After": "5"},
        )

    if r.status_code != 200:
        raise HTTPException(
            502, "TON transaction trace lookup failed"
        )

    data = r.json()

    if not isinstance(data, dict):
        raise HTTPException(
            502, "TON API returned an unexpected trace response"
        )

    return data


def walk_dicts(value):
    if isinstance(value, dict):
        yield value

        for child in value.values():
            yield from walk_dicts(child)

    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def tx_candidates(trace: dict):
    seen = set()

    for item in walk_dicts(trace):
        if (
            isinstance(item.get("in_msg"), dict)
            and item.get("utime") is not None
            and item.get("hash")
        ):
            h = str(item.get("hash")).lower()

            if h not in seen:
                seen.add(h)
                yield item


def normalize_tx_hash(raw: str) -> str:
    h = raw.strip()

    if "://" in h:
        h = (
            h.split("?")[0]
            .split("#")[0]
            .rstrip("/")
            .split("/")[-1]
        )

    if HEX64.match(h) or B64URL.match(h):
        return h

    raise HTTPException(
        400,
        "Invalid transaction hash (expected 64-character hex hash or explorer link)",
    )


# -------------------------------------------------------------- ENDPOINTS ---

@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "storm-payment-verification",
    }


@app.post("/create-payment")
async def create_payment(body: CreatePaymentRequest):
    if body.payment_type not in PAYMENTS:
        raise HTTPException(400, "Unknown payment type")

    user_id = validate_init_data(body.init_data)

    if not PAYMENT_WALLET:
        raise HTTPException(500, "PAYMENT_WALLET is not configured")

    try:
        parse_ton_address(PAYMENT_WALLET)
    except ValueError:
        raise HTTPException(
            500, "PAYMENT_WALLET is not a valid TON address"
        )

    now = utcnow().replace(microsecond=0)
    expires = now + timedelta(seconds=PAYMENT_WINDOW_SECONDS)

    r = await sb(
        "GET",
        "payment_requests",
        params={
            "telegram_user_id": f"eq.{user_id}",
            "status": "eq.pending",
            "expires_at": f"gt.{now.isoformat()}",
            "select": "id",
            "limit": "5",
        },
    )

    if r.status_code != 200:
        raise HTTPException(
            502, "Could not check existing payment requests"
        )

    if len(r.json()) >= 5:
        raise HTTPException(
            429, "Too many open payment requests, wait for them to expire"
        )

    record = {
        "id": str(uuid.uuid4()),
        "telegram_user_id": user_id,
        "payment_type": body.payment_type,
        "amount_nano": PAYMENTS[body.payment_type],
        "destination_address": PAYMENT_WALLET,
        "unique_comment": None,
        "status": "pending",
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
    }

    saved = await sb(
        "POST",
        "payment_requests",
        body=record,
    )

    if saved.status_code not in (200, 201):
        logger.error(
            "payment_requests insert failed: %s %s",
            saved.status_code,
            saved.text[:300],
        )
        raise HTTPException(
            502, "Could not create payment request"
        )

    return {
        "ok": True,
        "payment_request_id": record["id"],
        "payment_type": body.payment_type,
        "amount_ton": record["amount_nano"] / 1_000_000_000,
        "amount_nano": record["amount_nano"],
        "destination_address": PAYMENT_WALLET,
        "expires_in": PAYMENT_WINDOW_SECONDS,
        "created_at": iso_z(now),
        "expires_at": iso_z(expires),
        "server_time": iso_z(utcnow()),
    }


@app.post("/verify-payment")
async def verify_payment(body: VerifyRequest):
    user_id = validate_init_data(body.init_data)
    request_id = str(body.payment_request_id)
    submitted_hash = normalize_tx_hash(body.tx_hash)

    req = await get_payment_request(request_id)

    if not req or req.get("telegram_user_id") != user_id:
        raise HTTPException(404, "Payment request not found")

    if req["status"] == "expired":
        raise HTTPException(
            410, "Payment request expired. Create a new payment request."
        )

    if req["status"] != "pending":
        raise HTTPException(409, "Payment request already used")

    try:
        created_at = parse_ts(req["created_at"])
        expires_at = parse_ts(req["expires_at"])
    except Exception:
        raise HTTPException(
            500, "Stored payment request has invalid timestamps"
        )

    if utcnow() > expires_at:
        await set_request_status(request_id, "expired")
        raise HTTPException(
            410, "Payment request expired. Create a new payment request."
        )

    if not PAYMENT_WALLET:
        raise HTTPException(500, "PAYMENT_WALLET is not configured")

    try:
        parse_ton_address(PAYMENT_WALLET)
    except ValueError:
        raise HTTPException(
            500, "PAYMENT_WALLET is not a valid TON address"
        )

    # Resolve the sender-side wallet hash to its TON trace.
    trace = await fetch_trace(submitted_hash)

    matches = []

    for tx in tx_candidates(trace):
        in_msg = tx.get("in_msg")

        if not isinstance(in_msg, dict):
            continue

        if tx.get("aborted") is True or tx.get("success") is not True:
            continue

        if (
            in_msg.get("msg_type") != "int_msg"
            or in_msg.get("bounced") is True
        ):
            continue

        destination = addr_str(in_msg.get("destination"))
        account = addr_str(tx.get("account"))

        if not same_address(destination, PAYMENT_WALLET):
            continue

        if account is not None and not same_address(
            account, PAYMENT_WALLET
        ):
            continue

        try:
            paid_nano = int(in_msg.get("value"))
        except (TypeError, ValueError):
            continue

        if paid_nano != int(req["amount_nano"]):
            continue

        utime = tx.get("utime")

        if isinstance(utime, bool) or not isinstance(utime, int):
            continue

        if not (
            int(created_at.timestamp())
            <= utime
            <= int(expires_at.timestamp())
        ):
            continue

        canonical_hash = str(tx.get("hash") or "").lower()

        if HEX64.match(canonical_hash):
            matches.append(
                (tx, in_msg, canonical_hash, paid_nano)
            )

    unique = {
        item[2]: item
        for item in matches
    }

    if not unique:
        raise HTTPException(
            400,
            "No successful payment with the exact amount to the STORM wallet was found within 4 minutes",
        )

    if len(unique) != 1:
        raise HTTPException(
            400,
            "More than one matching payment was found; contact support",
        )

    tx, in_msg, tx_hash, paid_nano = next(
        iter(unique.values())
    )

    sender = addr_str(in_msg.get("source"))

    # Supabase atomically marks the request verified and claims the hash once.
    claim = await sb(
        "POST",
        "rpc/claim_payment_request",
        prefer=None,
        body={
            "p_request_id": request_id,
            "p_telegram_user_id": user_id,
            "p_tx_hash": tx_hash,
            "p_sender_address": sender,
        },
    )

    if claim.status_code != 200:
        logger.error(
            "claim rpc failed: %s %s",
            claim.status_code,
            claim.text[:300],
        )
        raise HTTPException(
            502, "Could not save payment claim"
        )

    result = claim.json()

    if not result.get("ok"):
        if result.get("reason") == "tx_already_claimed":
            raise HTTPException(
                409, "This transaction hash has already been used"
            )

        raise HTTPException(
            409, "Payment request was already used"
        )

    return {
        "ok": True,
        "verified": True,
        "payment_request_id": request_id,
        "payment_type": req["payment_type"],
        "amount_nano": paid_nano,
        "telegram_user_id": user_id,
        "tx_hash": tx_hash,
        "submitted_hash": submitted_hash,
    }
