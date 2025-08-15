
# FIN-GPT FastAPI OAuth Demo (Render-ready, fixed)

- OAuth 2.0 (Authorization Code + PKCE) + protected API
- SQLite seeded with demo users and data
- Proper OpenAPI `securitySchemes` (HTTP Bearer) and full `servers.url`
- Admin endpoint modelled with Pydantic

## Demo users
- arun@example.com / test1234
- riya@example.com / test1234
- vikky@example.com / test1234

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="s9SOk5AlF7_D8xfTNaBeOPKKu3OYo4dkaQXfEHyKIeU"
export ADMIN_TOKEN="z2hSQovrFXqCTd53hiuQdzE1f836DaP6"
export OAUTH_CLIENT_ID="customgpt-demo"
export OAUTH_CLIENT_SECRET="0IwoGJFxShdyu3DWsSY0a-TuaWovBBO0"
export ALLOW_REDIRECT_PREFIX="https://chat.openai.com/"
export PUBLIC_BASE_URL="http://127.0.0.1:8000"
uvicorn app.main:app --reload --port 8000
```
Open `/docs`.
