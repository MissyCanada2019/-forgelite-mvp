import os
import time
import secrets
import jwt
import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from api.owner import is_owner

router = APIRouter()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv(
    "GITHUB_REDIRECT_URI",
    "http://localhost:8000/api/github/callback"
)
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRES_SECONDS = int(os.getenv("JWT_EXPIRES_SECONDS", "604800"))

_OAUTH_STATE = set()

def _make_jwt(payload: dict) -> str:
    now = int(time.time())
    payload = {
        **payload,
        "iat": now,
        "exp": now + JWT_EXPIRES_SECONDS,
        "iss": "forgelite",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

@router.get("/api/github/login")
async def github_login():
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Missing GITHUB_CLIENT_ID")

    state = secrets.token_urlsafe(32)
    _OAUTH_STATE.add(state)

    return RedirectResponse(
        "https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=read:user user:email"
        f"&state={state}"
    )

@router.get("/api/github/callback")
async def github_callback(code: str | None = None, state: str | None = None):
    if not code or state not in _OAUTH_STATE:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    _OAUTH_STATE.remove(state)

    async with httpx.AsyncClient(timeout=20) as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI,
            },
        )

        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="OAuth token exchange failed")

        user = (await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"}
        )).json()

        emails = (await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {access_token}"}
        )).json()

    email = next(
        (e["email"] for e in emails if e.get("primary") and e.get("verified")),
        None,
    )

    if not email:
        raise HTTPException(status_code=400, detail="No verified email returned")

    role = "owner" if is_owner(email) else "user"

    session = _make_jwt({
        "email": email,
        "role": role,
        "github_login": user.get("login"),
    })

    resp = RedirectResponse(FRONTEND_BASE_URL)
    resp.set_cookie(
        "forgelite_session",
        session,
        httponly=True,
        samesite="lax",
    )
    return resp

@router.get("/api/me")
async def me(request: Request):
    token = request.cookies.get("forgelite_session")
    if not token:
        return {"authenticated": False}

    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"authenticated": True, **data}
    except Exception:
        return {"authenticated": False}

@router.post("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("forgelite_session")
    return resp
