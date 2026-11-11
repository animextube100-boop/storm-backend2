# STORM payment verification backend (initial scaffold)

## Deploy
1. Upload the contents of this ZIP to the root of your separate private GitHub repository.
2. Import that repository into Vercel as a new project.
3. Add the environment variables below in Vercel → Settings → Environment Variables.
4. Redeploy after adding them.

## Environment variables
- BOT_TOKEN: Telegram bot token (secret).
- TONAPI_KEY: TONAPI API key.
- SUPABASE_URL: https://fntgxukftaumztacprwe.supabase.co
- SUPABASE_SECRET_KEY: your Supabase server-side secret key (sb_secret_...).
- PAYMENT_WALLET: UQCo0-D4DWT4Q99BJ35ONA7wduh_qtNwwpni55UyMhsFcY-x
- FRONTEND_ORIGIN: exact frontend deployment origin, with no trailing slash.

## Test
Open https://YOUR-BACKEND.vercel.app/health. Expected:
{"ok":true,"service":"storm-payment-verification"}

## Important limitations
This is an initial scaffold, not a production-ready payment-crediting system.
- Destination matching is exact. TONAPI may return a raw address while your configured wallet is friendly-format, so a valid payment may be rejected until address normalization is added and tested.
- A shared receiving wallet plus transaction hash does not prove which Telegram user made the payment. Use unique memo/order attribution or authenticated wallet ownership before production.
- This endpoint records a verified claim only. It does not activate miners or credit STORM.
- Do not use mainnet payments for testing until end-to-end checks are complete. Never put secrets in frontend HTML or GitHub.
