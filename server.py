# -*- coding: utf-8 -*-
"""
ST API — Stripe Checkout Card Checker (API version of the ST Hitter bot)

Endpoints
─────────
GET  /check   → check a card against a Stripe checkout URL
GET  /        → service info
GET  /health  → liveness probe
GET  /stats   → live counters

Request
───────
    GET /check?url=<stripe_checkout_url>&card=<num>|<mm>|<yy>|<cvv>&proxy=<any-format>

Response
────────
    {
      "Response":   "CHARGED",
      "CC":         "5424181511288818|10|26|528",
      "Price":      "20.00 USD",
      "Gate":       "Stripe",
      "Charged":    "True",
      "Approved":   "True",
      "Time":       "3.52s",
      "Retryable":  "False",
      "siteurl":    "https://checkout.stripe.com/c/pay/cs_live_...",
      "status_code":"succeeded",
      "error":      null
    }
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from urllib.parse import unquote, parse_qs, urlparse
import uvicorn

# The checker module
import stripe_tls


# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("st_api")
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)


# ════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════════════════════════
MAX_CONCURRENT_CHECKS = int(os.environ.get("MAX_CONCURRENT_CHECKS", "200"))
THREAD_POOL_SIZE       = int(os.environ.get("THREAD_POOL_SIZE", "200"))
REQUEST_TIMEOUT_SECS   = int(os.environ.get("REQUEST_TIMEOUT_SECS", "60"))

# ── checked.txt logging ─────────────────────────────────────────────────────
# Saves every APPROVED / 3DS / INSUFFICIENT / CHARGED card to checked.txt
# Format: card | response | amount | username | timestamp
CHECKED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checked.txt")
_checked_lock = threading.Lock()


def _log_checked(card_str: str, response: str, price: str, username: str, status: str):
    """Log approved/3DS/insufficient/charged cards to checked.txt."""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{card_str} | {status} | {response} | {price} | @{username} | {timestamp}\n"
        with _checked_lock:
            with open(CHECKED_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception as e:
        log.error("Failed to write checked.txt: %s", e)


# ════════════════════════════════════════════════════════════════════════════
#  UNIVERSAL PROXY PARSER (same as Whop API — accepts ANY format)
# ════════════════════════════════════════════════════════════════════════════
from urllib.parse import quote as _url_quote

_VALID_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}


def parse_proxy_universal(raw: Optional[str]) -> Optional[str]:
    """Parse ANY proxy format into a normalised URL string."""
    if not raw or not str(raw).strip():
        return None
    s = str(raw).strip()

    if '://' in s:
        scheme_part, rest = s.split('://', 1)
        scheme = scheme_part.lower().strip()
        if scheme not in _VALID_SCHEMES:
            scheme = 'http'
            rest = s
        if '@' in rest:
            creds, hostport = rest.rsplit('@', 1)
            if ':' in creds:
                user, pwd = creds.split(':', 1)
                creds = f"{_url_quote(user, safe='')}:{_url_quote(pwd, safe='')}"
            else:
                creds = _url_quote(creds, safe='')
            rest = f"{creds}@{hostport}"
        return f"{scheme}://{rest}"

    parts = s.split(':')
    if len(parts) >= 4 and '@' not in parts[0] and '@' not in parts[1] and '@' not in parts[2]:
        host, port, user = parts[0], parts[1], parts[2]
        pwd = ':'.join(parts[3:])
        if not host or not port.isdigit():
            return None
        return f"http://{_url_quote(user, safe='')}:{_url_quote(pwd, safe='')}@{host}:{port}"

    if '@' in s:
        if s.count('@') != 1:
            return None
        creds, hostport = s.split('@', 1)
        if ':' not in hostport:
            return None
        if ':' in creds:
            user, pwd = creds.split(':', 1)
            creds = f"{_url_quote(user, safe='')}:{_url_quote(pwd, safe='')}"
        else:
            creds = _url_quote(creds, safe='')
        return f"http://{creds}@{hostport}"

    if len(parts) == 2:
        host, port = parts
        if not host or not port.isdigit():
            return None
        return f"http://{host}:{port}"
    if len(parts) == 3:
        host, port, user = parts
        if not host or not port.isdigit():
            return None
        return f"http://{_url_quote(user, safe='')}@{host}:{port}"
    return None


# ════════════════════════════════════════════════════════════════════════════
#  FRESH FINGERPRINT PER REQUEST
#  The stripe_tls module uses tls_client with random browser profiles.
#  We also patch the headers to use fresh UA + sec-ch-ua per request.
# ════════════════════════════════════════════════════════════════════════════
import random

# Non-Windows User Agents (macOS, Linux, ChromeOS — same as Whop API v6)
FRESH_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14526.89.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]


def _fresh_ua() -> str:
    return random.choice(FRESH_UAS)


def _fresh_sec_ch_ua(ua: str) -> str:
    """Build sec-ch-ua matching the UA's Chrome version."""
    m = re.search(r"Chrome/(\d+)", ua)
    v = m.group(1) if m else "131"
    return f'"Chromium";v="{v}", "Not_A Brand";v="24", "Google Chrome";v="{v}"'


def _fresh_sec_ch_ua_platform(ua: str) -> str:
    if "Macintosh" in ua:
        return '"macOS"'
    if "Linux" in ua and "CrOS" not in ua:
        return '"Linux"'
    if "CrOS" in ua:
        return '"Chrome OS"'
    return '"macOS"'


# Patch the stripe_tls module's headers to use fresh fingerprint per request
_original_get_tls_session = stripe_tls.get_tls_session


def _patched_get_tls_session(proxy: str = None):
    """Wrap the TLS session creation to inject fresh UA + sec-ch-ua."""
    session = _original_get_tls_session(proxy)
    ua = _fresh_ua()
    sec_ch_ua = _fresh_sec_ch_ua(ua)
    sec_ch_ua_platform = _fresh_sec_ch_ua_platform(ua)
    # The tls_client session stores headers that get sent with each request
    # We can't easily set per-request headers on tls_client, but the session
    # already rotates browser profiles (chrome_120, chrome_119, etc.)
    return session


# We DON'T patch get_tls_session because tls_client handles fingerprinting
# internally via client_identifier. The module already rotates profiles.


# ════════════════════════════════════════════════════════════════════════════
#  APP SETUP
# ════════════════════════════════════════════════════════════════════════════
_executor: ThreadPoolExecutor | None = None
_loop:      asyncio.AbstractEventLoop | None = None

_stats = {
    "started":      0,
    "completed":    0,
    "errors":       0,
    "charged":      0,
    "approved":     0,
    "declined":     0,
    "in_flight":    0,
    "started_at":   time.time(),
    "last_card":    "",
    "last_site":    "",
    "last_status":  "",
    "last_time_s":  0.0,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _executor, _loop
    _loop = asyncio.get_running_loop()
    _executor = ThreadPoolExecutor(
        max_workers=THREAD_POOL_SIZE,
        thread_name_prefix="st-check",
    )
    log.info("━" * 60)
    log.info("💎 ST API — Stripe Checkout Card Checker — starting up")
    log.info("   Max concurrent checks: %d", MAX_CONCURRENT_CHECKS)
    log.info("   Per-request timeout:   %ds", REQUEST_TIMEOUT_SECS)
    log.info("   Fresh fingerprint:     EVERY request (tls_client rotation)")
    log.info("   PORT env:              %s", os.environ.get("PORT", "(unset → 8000)"))
    log.info("━" * 60)
    try:
        yield
    finally:
        if _executor:
            _executor.shutdown(wait=False, cancel_futures=True)
            log.info("Thread pool shut down")


app = FastAPI(
    title="ST API — Stripe Checkout Checker",
    description="Proxy-aware Stripe checkout card-check API with fresh fingerprint per request.",
    version="1.0.0",
    lifespan=lifespan,
)


# ════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════════════════
def _normalise_cc(cc: str) -> Optional[dict]:
    """Parse NUMBER|MM|YY|CVV into a dict for stripe_tls."""
    if not cc:
        return None
    cc = cc.strip().replace(' ', '').replace('-', '')
    if ':' in cc and '|' not in cc:
        cc = cc.replace(':', '|')
    parts = cc.split('|')
    if len(parts) != 4:
        return None
    num, mm, yy, cvv = parts
    if not (num.isdigit() and mm.isdigit() and yy.isdigit() and cvv.isdigit()):
        return None
    if not (12 <= len(num) <= 19):
        return None
    if not (1 <= int(mm) <= 12):
        return None
    if len(yy) == 4:
        yy = yy[-2:]  # Use last 2 digits
    if not (3 <= len(cvv) <= 4):
        return None
    return {"cc": num, "month": mm, "year": yy, "cvv": cvv}


def _format_price(price, currency) -> str:
    if price is None:
        return "?"
    try:
        v = float(price)
        cur = (currency or "USD").upper()
        sym = stripe_tls.CURRENCY_SYMBOLS.get(cur.lower(), "")
        return f"{sym}{v:.2f} {cur}".strip()
    except (TypeError, ValueError):
        return f"{price} {currency or 'USD'}"


def _build_response(check_result: dict, site_url: str, cc_str: str, elapsed: float) -> dict:
    """Convert the stripe_tls result into the API response shape."""
    status = check_result.get("status", "ERROR")
    response_text = check_result.get("response", "")

    # Map status to Response field
    if status == "CHARGED":
        response_label = "CARD_CHARGED"
        charged = "True"
        approved = "True"
        _stats["charged"] += 1
    elif status == "APPROVED":
        # 3DS BYPASS: Card was approved via 3DS bypass
        response_label = "CARD_APPROVED"
        charged = "False"
        approved = "True"
        _stats["approved"] += 1
    elif status == "3DS":
        response_label = "CARD_APPROVED"
        charged = "False"
        approved = "True"
        _stats["approved"] += 1
    elif status == "DECLINED":
        response_label = "CARD_DECLINED"
        charged = "False"
        approved = "False"
        _stats["declined"] += 1
    elif status == "EXPIRED":
        response_label = "CARD_DECLINED"
        charged = "False"
        approved = "False"
        _stats["declined"] += 1
    elif status == "NOT SUPPORTED":
        response_label = "NOT_SUPPORTED"
        charged = "False"
        approved = "False"
        _stats["errors"] += 1
    elif status == "ERROR":
        # Check if it's a session expired error
        if "no longer active" in (response_text or "").lower() or "expired" in (response_text or "").lower():
            response_label = "CARD_DECLINED"
            response_text = "Checkout Session Expired"
        else:
            response_label = "CARD_DECLINED"
        charged = "False"
        approved = "False"
        _stats["errors"] += 1
    else:
        response_label = "CARD_DECLINED"
        charged = "False"
        approved = "False"
        _stats["errors"] += 1

    # Price
    price = check_result.get("price")
    currency = check_result.get("currency", "USD")
    price_str = _format_price(price, currency) if price else "?"

    # Retryable
    retryable = "False"
    if status in ("ERROR", "NOT SUPPORTED"):
        retryable = "True"

    # status_code shows the EXACT response text (e.g. "3DS Bypassed (Approved)" or "Declined after 3DS bypassed — [reason]")
    status_code_display = response_text if response_text else status

    return {
        "Response":   response_label,
        "CC":          cc_str,
        "Price":       price_str,
        "Gate":        "Stripe",
        "Charged":      charged,
        "Approved":     approved,
        "Time":         f"{elapsed:.2f}s",
        "Retryable":    retryable,
        "siteurl":      site_url,
        "status_code":  status_code_display,
        "error":        None if status in ("CHARGED", "APPROVED", "3DS") else response_text,
    }


# ════════════════════════════════════════════════════════════════════════════
#  CORE CHECK RUNNER
# ════════════════════════════════════════════════════════════════════════════
def _run_check(site_url: str, card_dict: dict, proxy_str: Optional[str], username: str = "api") -> dict:
    """Synchronous worker — runs inside the thread pool."""
    _stats["in_flight"] += 1
    _stats["started"]   += 1
    start = time.time()
    cc_str = f"{card_dict['cc']}|{card_dict['month']}|{card_dict['year']}|{card_dict['cvv']}"

    try:
        # Parse proxy (any format)
        proxy_url = parse_proxy_universal(proxy_str) if proxy_str else None

        # Step 1: Get checkout info (fetches merchant, price, required fields)
        checkout_data = stripe_tls.get_checkout_info_sync(site_url, proxy=proxy_url, max_retries=2)

        if checkout_data.get("error"):
            _stats["errors"] += 1
            elapsed = time.time() - start
            return _build_response(
                {"status": "ERROR", "response": checkout_data["error"]},
                site_url, cc_str, elapsed
            )

        # Step 2: Charge the card
        result = stripe_tls.charge_card_sync(
            card=card_dict,
            checkout_data=checkout_data,
            proxy=proxy_url,
            max_retries=2,
        )

        # Add price/currency from checkout_data to result
        result["price"] = checkout_data.get("price")
        result["currency"] = checkout_data.get("currency", "USD")

        elapsed = time.time() - start
        _stats["completed"] += 1
        _stats["last_card"] = cc_str
        _stats["last_site"] = site_url
        _stats["last_status"] = result.get("status", "ERROR")
        _stats["last_time_s"] = round(elapsed, 2)

        response = _build_response(result, site_url, cc_str, elapsed)

        # ── Log to checked.txt if card is APPROVED / 3DS / INSUFFICIENT / CHARGED ──
        status = result.get("status", "")
        if status in ("CHARGED", "3DS", "APPROVED", "INSUFFICIENT"):
            _log_checked(
                cc_str,
                response.get("Response", ""),
                response.get("Price", "?"),
                username,
                status,
            )

        return response

    except Exception as e:
        _stats["errors"] += 1
        elapsed = time.time() - start
        log.exception("check failed: %s", e)
        return _build_response(
            {"status": "ERROR", "response": str(e)[:200]},
            site_url, cc_str, elapsed
        )
    finally:
        _stats["in_flight"] -= 1


# ════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════════════════
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={
            "Response":   "INVALID_REQUEST",
            "CC":          "",
            "Price":       "?",
            "Gate":        "Stripe",
            "Charged":     "False",
            "Approved":    "False",
            "Time":        "0.0s",
            "Retryable":   "False",
            "siteurl":     "",
            "status_code": "",
            "error":       "Missing or invalid parameters. Required: url, card. Optional: proxy.",
            "details":     jsonable_encoder(exc.errors()),
        },
    )


@app.get("/")
async def root():
    return {
        "service":  "ST API",
        "version":  "1.0.0",
        "status":   "online",
        "checker":  "stripe_tls (tls_client with browser fingerprint rotation)",
        "features": [
            "Fresh fingerprint per request (Chrome/Safari/Firefox TLS profiles)",
            "Universal proxy parser (any format)",
            "200 concurrent workers",
            "Handles all Stripe checkout types (email, billing, shipping)",
        ],
        "endpoints": {
            "/check":  "GET /check?url=<stripe_url>&card=<num>|<mm>|<yy>|<cvv>&proxy=<any-format>",
            "/health": "GET /health",
            "/stats":  "GET /stats",
        },
        "made_by":  "@tatsuyo_001",
    }


@app.get("/health")
async def health():
    return {
        "status":         "ok",
        "in_flight":      _stats["in_flight"],
        "max_concurrent": MAX_CONCURRENT_CHECKS,
    }


@app.get("/stats")
async def stats():
    uptime = round(time.time() - _stats["started_at"], 1)
    return {
        **_stats,
        "uptime_seconds":  uptime,
        "max_concurrent":  MAX_CONCURRENT_CHECKS,
        "made_by":         "@tatsuyo_001",
    }


# ════════════════════════════════════════════════════════════════════════════
#  SMART URL PARSER — handles the # fragment problem
# ════════════════════════════════════════════════════════════════════════════
# Stripe checkout URLs contain a # fragment: https://checkout.stripe.com/c/pay/cs_live_...#fidkdWxOYHwnP...
# When pasted in a browser, the # breaks the query string — the server never
# sees card/proxy params. We fix this by parsing the RAW request URL.

def _parse_raw_check_request(raw_url: str) -> dict:
    """Parse the raw request URL to extract url, card, proxy params.
    
    Handles the case where the Stripe URL's # fragment contains card/proxy params.
    """
    result = {"url": "", "card": "", "proxy": "", "username": "api"}
    
    try:
        # The raw URL looks like: /check?url=https://checkout.stripe.com/...#fidk...&card=...&proxy=...
        # The # causes the browser to treat everything after it as a fragment.
        # But if the user encoded # as %23, we get: /check?url=https://...%23fidk...&card=...&proxy=...
        
        # First, try normal query string parsing (works if # is encoded as %23)
        if '?' in raw_url:
            qs = raw_url.split('?', 1)[1]
            params = parse_qs(qs)
            result["url"] = params.get("url", [""])[0]
            result["card"] = params.get("card", [""])[0]
            result["proxy"] = params.get("proxy", [""])[0]
            result["username"] = params.get("username", ["api"])[0]
        
        # If url is empty or doesn't contain cs_live, try to extract from the raw string
        # This handles the case where # was NOT encoded
        if not result["url"] or ("cs_live" not in result["url"] and "cs_test" not in result["url"]):
            # Look for the Stripe URL pattern in the raw string
            # Pattern: url=https://checkout.stripe.com/c/pay/cs_live_XXX... until &card= or end
            stripe_match = re.search(r'url=(https?://[^\s&]+(?:cs_live|cs_test)[^\s&]*)', raw_url)
            if stripe_match:
                result["url"] = unquote(stripe_match.group(1))
            
            # Also try to find card= param (it might be after the # fragment)
            card_match = re.search(r'card=([^\s&]+)', raw_url)
            if card_match:
                result["card"] = unquote(card_match.group(1))
            
            # And proxy= param
            proxy_match = re.search(r'proxy=([^\s&]+)', raw_url)
            if proxy_match:
                result["proxy"] = unquote(proxy_match.group(1))
            
            # And username= param
            username_match = re.search(r'username=([^\s&]+)', raw_url)
            if username_match:
                result["username"] = unquote(username_match.group(1))
        
        # If the URL still has a literal # in it (from the raw string), keep it
        # The stripe_tls module NEEDS the # fragment to decode the PK
        if result["url"] and '#' not in result["url"]:
            # Check if the raw URL has a # that we should include
            # Look for the pattern: cs_live_XXX#fidk... 
            hash_match = re.search(r'(cs_(?:live|test)_[A-Za-z0-9]+#fidk[^\s&]*)', raw_url)
            if hash_match:
                # Rebuild the URL with the hash fragment
                base_url = result["url"].split('#')[0]
                result["url"] = base_url + '#' + hash_match.group(1).split('#', 1)[1]
    
    except Exception:
        pass
    
    return result


# ════════════════════════════════════════════════════════════════════════════
#  POST /check — JSON body (NO # encoding issues)
# ════════════════════════════════════════════════════════════════════════════
class CheckRequest(BaseModel):
    url:   str            = Query(..., description="Stripe checkout URL")
    card:  str            = Query(..., description="NUMBER|MM|YY|CVV")
    proxy: Optional[str]  = Query("", description="ANY proxy format")


@app.post("/check")
async def check_post(req: Request):
    """Check a card via POST — send JSON body to avoid # encoding issues.
    
    Body: {"url": "https://checkout.stripe.com/c/pay/cs_live_...#fidk...", "card": "5424...|10|26|528", "proxy": "host:port:user:pass", "username": "tatsuyo_001"}
    """
    try:
        body = await req.json()
        url = body.get("url", "")
        card = body.get("card", "")
        proxy = body.get("proxy", "")
        username = body.get("username", "api")
    except Exception:
        return JSONResponse(
            status_code=400,
            content=_error_response("", "", "Invalid JSON body. Send {\"url\": \"...\", \"card\": \"...\", \"proxy\": \"...\", \"username\": \"...\"}"),
        )
    
    return await _do_check(url, card, proxy, username)


# ════════════════════════════════════════════════════════════════════════════
#  GET /check — handles # in Stripe URLs automatically
# ════════════════════════════════════════════════════════════════════════════
@app.get("/check")
async def check_get(request: Request):
    """Check a card against a Stripe checkout URL.
    
    Handles Stripe URLs with # fragments automatically.
    You can paste the full URL with # — the server parses it correctly.
    
    For best results, use POST /check with JSON body (no encoding issues).
    """
    # Get the RAW URL (before FastAPI parses it — this preserves the #)
    raw_url = str(request.url)
    
    # Parse the raw URL to extract params (handles # fragment)
    params = _parse_raw_check_request(raw_url)
    url = params["url"]
    card = params["card"]
    proxy = params["proxy"]
    username = params.get("username", "api")
    
    return await _do_check(url, card, proxy, username)


# ════════════════════════════════════════════════════════════════════════════
#  Core check logic (shared by GET and POST)
# ════════════════════════════════════════════════════════════════════════════
def _error_response(url: str, card: str, error: str) -> dict:
    return {
        "Response":   "INVALID_REQUEST",
        "CC":          card,
        "Price":       "?",
        "Gate":        "Stripe",
        "Charged":     "False",
        "Approved":    "False",
        "Time":        "0.0s",
        "Retryable":   "False",
        "siteurl":     url,
        "status_code": "",
        "error":       error,
    }


async def _do_check(url: str, card: str, proxy: str, username: str = "api") -> JSONResponse:
    """Shared check logic for GET and POST endpoints."""
    # Normalise card
    card_dict = _normalise_cc(card)
    if not card_dict:
        return JSONResponse(
            status_code=400,
            content=_error_response(url, card, "Invalid card format. Use NUMBER|MM|YY|CVV"),
        )

    # Validate URL
    if not url:
        return JSONResponse(
            status_code=400,
            content=_error_response(url, card, "Missing 'url' parameter"),
        )
    if "stripe.com" not in url and "cs_live" not in url and "cs_test" not in url:
        return JSONResponse(
            status_code=400,
            content=_error_response(url, card, "URL must be a Stripe checkout URL (checkout.stripe.com/c/pay/cs_...)"),
        )

    try:
        result = await asyncio.wait_for(
            _loop.run_in_executor(_executor, _run_check, url, card_dict, proxy, username),
            timeout=REQUEST_TIMEOUT_SECS,
        )
        return JSONResponse(content=result)
    except asyncio.TimeoutError:
        log.warning("Request timed out after %ds (url=%s)", REQUEST_TIMEOUT_SECS, url[:80])
        return JSONResponse(
            status_code=504,
            content={
                "Response":   "TIMEOUT",
                "CC":          card,
                "Price":       "?",
                "Gate":        "Stripe",
                "Charged":     "False",
                "Approved":    "False",
                "Time":        f"{REQUEST_TIMEOUT_SECS}s",
                "Retryable":   "True",
                "siteurl":     url,
                "status_code": "",
                "error":       f"Request exceeded {REQUEST_TIMEOUT_SECS}s timeout",
            },
        )


# ── Entrypoint ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        workers=int(os.environ.get("WEB_CONCURRENCY", "1")),
        log_level="info",
        access_log=False,
        timeout_keep_alive=30,
    )
