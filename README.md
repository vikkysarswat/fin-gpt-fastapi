# FIN-GPT FastAPI OAuth Demo (Render-ready)

This is a minimal **FastAPI** web app that acts as **both** an OAuth 2.0 Authorization Server (Authorization Code + PKCE) and a protected **Resource API** for user-specific brokerage-like data (trades, PnL, ledger, holdings, funds, profile).

It is designed to be used by **Custom GPT Actions** with **OAuth** so that each user signs in and the GPT can only fetch **their** data.

## Quick Start (Locally)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="4Mu_gDal4kzQpeQs10zoTbKxVlRIS8eolgs9HwAhRPM"
export ADMIN_TOKEN="YCcp0krQqj8BeQSjrIk-9tDDFiQ9QT8z"
export OAUTH_CLIENT_ID="customgpt-demo"
export OAUTH_CLIENT_SECRET="WFJbloooUmoxbfJpJvG7NHwWISsnI2jV"
export ALLOW_REDIRECT_PREFIX="https://chat.openai.com/"
uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000 to see a welcome page.
API docs: http://127.0.0.1:8000/docs

## Default demo users

| email              | password   | phone       | client_id |
|--------------------|------------|-------------|-----------|
| arun@example.com   | test1234   | +91-90000   | ARUN01    |
| riya@example.com   | test1234   | +91-90001   | RIYA01    |
| vikky@example.com  | test1234   | +91-90002   | VIKKY01   |

## OAuth Client for GPT

A default OAuth client is created on startup:

- **Client ID**: `customgpt-demo`
- **Client Secret**: `WFJbloooUmoxbfJpJvG7NHwWISsnI2jV`
- **Allowed Redirect Prefix**: `https://chat.openai.com/` (any path under this host)

You can add/change redirect URIs using the admin endpoint (see below).

## Admin endpoints

- `POST /admin/add_redirect` with Header `X-Admin-Token: YCcp0krQqj8BeQSjrIk-9tDDFiQ9QT8z` and JSON:
  ```json
  {"client_id": "customgpt-demo", "redirect_uri": "https://chat.openai.com/aip/*"}
  ```

## OAuth Endpoints

- `GET /oauth/authorize` (with PKCE required)
- `POST /oauth/token`
- `GET /oauth/userinfo` (Bearer token)

## Protected API Endpoints (Bearer token)

- `GET /api/me`
- `GET /api/trades`
- `GET /api/pnl`
- `GET /api/ledger`
- `GET /api/holdings`
- `GET /api/funds`

These return only the authenticated user's records.

## Notes

- **Demo-only**: Simplified OAuth server for POC. Do not use as-is for production without security reviews.
- Tokens are **JWT HS256**, signed by `SECRET_KEY`, with 1 hour expiry; refresh tokens expire in 14 days.
- DB is SQLite (`data.db`) auto-created and seeded on first run.
- Consent screen is included; you can edit `templates/consent.html` and `templates/login.html`.
- OpenAPI schema: `/openapi.json`. GPT Actions can import your live schema via URL.
