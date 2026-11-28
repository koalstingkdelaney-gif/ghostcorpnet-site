"""Owner-authenticated, same-origin Quest gateway.

The Quest client receives only an HttpOnly session cookie, never the backend
bearer token. Configure a GitHub OAuth App and the environment variables listed
in backend/README.md before enabling this router in production.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

router = APIRouter()
DB_PATH = Path(os.getenv("GHOSTCORP_DB_PATH", "data/ghostcorp.db"))
CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
OWNER_LOGIN = os.getenv("GHOSTCORP_OWNER_GITHUB_LOGIN", "").strip().lower()
SESSION_SECRET = os.getenv("GHOSTCORP_SESSION_SECRET", "")
PUBLIC_ORIGIN = os.getenv("GHOSTCORP_PUBLIC_ORIGIN", "").rstrip("/")
SESSION_COOKIE = "__Host-ghostcorp_owner"
STATE_COOKIE = "__Host-ghostcorp_oauth_state"
SESSION_TTL = 8 * 60 * 60


def configured() -> bool:
    return all((CLIENT_ID, CLIENT_SECRET, OWNER_LOGIN, SESSION_SECRET, PUBLIC_ORIGIN.startswith("https://")))


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def sign_session(login: str, expires: int) -> str:
    payload = b64(json.dumps({"login": login, "exp": expires}, separators=(",", ":")).encode())
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    return payload + "." + b64(signature)


def session_login(request: Request) -> str | None:
    if not SESSION_SECRET:
        return None
    token = request.cookies.get(SESSION_COOKIE, "")
    try:
        payload, signature = token.split(".", 1)
        expected = b64(hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        login = str(data.get("login", "")).lower()
        return login if login == OWNER_LOGIN and OWNER_LOGIN else None
    except Exception:
        return None


@router.get("/auth/status")
def auth_status():
    return {"configured": configured(), "provider": "github"}


@router.get("/auth/github/start")
def github_start():
    if not configured():
        raise HTTPException(status_code=503, detail="Owner sign-in is not configured")
    state = secrets.token_urlsafe(32)
    callback = PUBLIC_ORIGIN + "/auth/github/callback"
    params = urlencode({"client_id": CLIENT_ID, "redirect_uri": callback, "scope": "read:user", "state": state})
    response = RedirectResponse("https://github.com/login/oauth/authorize?" + params, status_code=302)
    response.set_cookie(STATE_COOKIE, state, max_age=600, httponly=True, secure=True, samesite="lax", path="/")
    return response


@router.get("/auth/github/callback")
async def github_callback(request: Request):
    if not configured():
        raise HTTPException(status_code=503, detail="Owner sign-in is not configured")
    state = request.query_params.get("state", "")
    saved_state = request.cookies.get(STATE_COOKIE, "")
    code = request.query_params.get("code", "")
    if not state or not saved_state or not hmac.compare_digest(state, saved_state) or not code:
        raise HTTPException(status_code=400, detail="OAuth state validation failed")
    callback = PUBLIC_ORIGIN + "/auth/github/callback"
    async with httpx.AsyncClient(timeout=12.0) as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code, "redirect_uri": callback},
        )
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="GitHub authorization failed")
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": "Bearer " + access_token, "Accept": "application/vnd.github+json"},
        )
        user_response.raise_for_status()
        login = str(user_response.json().get("login", "")).lower()
    if not hmac.compare_digest(login, OWNER_LOGIN):
        raise HTTPException(status_code=403, detail="This GitHub account is not authorized as the GhostCorp owner")
    response = RedirectResponse(PUBLIC_ORIGIN + "/vr/", status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/")
    response.set_cookie(
        SESSION_COOKIE, sign_session(login, int(time.time()) + SESSION_TTL),
        max_age=SESSION_TTL, httponly=True, secure=True, samesite="lax", path="/",
    )
    return response


@router.get("/auth/me")
def auth_me(request: Request):
    login = session_login(request)
    return {"authenticated": bool(login), "login": login if login else None}


@router.post("/auth/logout")
def auth_logout():
    response = Response(content=json.dumps({"ok": True}), media_type="application/json")
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/api/vr/session")
def vr_session(request: Request):
    login = session_login(request)
    if not login:
        raise HTTPException(status_code=401, detail="Owner sign-in required")
    return {"authenticated": True, "role": "owner"}


@router.get("/api/vr/world/snapshot")
def vr_world_snapshot(request: Request):
    if not session_login(request):
        raise HTTPException(status_code=401, detail="Owner sign-in required")
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="World database is not initialized")
    conn = db()
    try:
        rows = conn.execute(
            "SELECT entity_id,entity_type,data,revision,updated_at FROM world_state "
            "WHERE entity_type IN ('world','scene') ORDER BY entity_id"
        ).fetchall()
        cursor = conn.execute("SELECT COALESCE(MAX(seq),0) AS seq FROM events").fetchone()["seq"]
    finally:
        conn.close()
    entities = [{
        "entity_id": row["entity_id"], "entity_type": row["entity_type"],
        "data": json.loads(row["data"]), "revision": row["revision"], "updated_at": row["updated_at"]
    } for row in rows]
    return {"schema_version": 1, "entities": entities, "count": len(entities), "event_cursor": cursor}


@router.get("/api/vr/events")
def vr_events(request: Request, after: int = 0, limit: int = 100):
    if not session_login(request):
        raise HTTPException(status_code=401, detail="Owner sign-in required")
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="World database is not initialized")
    conn = db()
    try:
        rows = conn.execute(
            "SELECT seq,event_id,event_type,actor,correlation_id,schema_version,payload,created_at "
            "FROM events WHERE seq>? ORDER BY seq LIMIT ?",
            (max(0, after), max(1, min(limit, 200)))
        ).fetchall()
    finally:
        conn.close()
    return {"items": [{
        **{k: row[k] for k in ("seq", "event_id", "event_type", "actor", "correlation_id", "schema_version", "created_at")},
        "payload": json.loads(row["payload"])
    } for row in rows]}
