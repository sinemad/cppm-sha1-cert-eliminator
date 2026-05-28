"""FastAPI web application for the SHA-1 Certificate Eliminator."""

import asyncio
import os
from typing import Optional, Union

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pyclearpass import ApiPlatformCertificates, ClearPassAPILogin
from pydantic import BaseModel

from app.clearpass import (
    ClearPassConfig,
    fetch_all_trust_list,
    identify_sha1_certs,
    make_login,
    remove_cert,
    safe_serialize,
)

app = FastAPI(title="SHA-1 Certificate Eliminator", docs_url=None, redoc_url=None)

# Single-user in-memory state — sufficient for a local Docker tool
_config: Optional[ClearPassConfig] = None
_login: Optional[ClearPassAPILogin] = None


# ── Pydantic models ────────────────────────────────────────────────────────────

class ConfigRequest(BaseModel):
    server: str
    api_token: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    verify_ssl: bool = True


class DeleteRequest(BaseModel):
    ids: list[Union[str, int]]


# ── API routes (must be declared before StaticFiles mount) ─────────────────────

@app.get("/api/config")
async def get_config():
    """Return the current config including credentials (local tool — single-user only)."""
    if _config:
        return {
            "configured": True,
            "server": _config.server,
            "auth_type": "api_token" if _config.api_token else "client_credentials",
            "api_token": _config.api_token,
            "client_id": _config.client_id,
            "client_secret": _config.client_secret,
            "verify_ssl": _config.verify_ssl,
        }

    # Not yet connected — return env var values so the form can pre-populate
    env_verify = os.environ.get("CLEARPASS_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
    env_token  = os.environ.get("CLEARPASS_API_TOKEN", "")
    env_id     = os.environ.get("CLEARPASS_CLIENT_ID", "")
    env_secret = os.environ.get("CLEARPASS_CLIENT_SECRET", "")
    return {
        "configured": False,
        "server": os.environ.get("CLEARPASS_SERVER", ""),
        "auth_type": "client_credentials" if (env_id or env_secret) else "api_token",
        "api_token": env_token,
        "client_id": env_id,
        "client_secret": env_secret,
        "verify_ssl": env_verify,
    }


@app.post("/api/config")
async def save_config(req: ConfigRequest):
    """Validate credentials by test-connecting, then store config in memory."""
    global _config, _login

    if not req.server:
        raise HTTPException(400, "Server URL is required.")
    if not req.api_token and not (req.client_id and req.client_secret):
        raise HTTPException(400, "Provide api_token or both client_id and client_secret.")

    config = ClearPassConfig(
        server=req.server.rstrip("/"),
        api_token=req.api_token or None,
        client_id=req.client_id or None,
        client_secret=req.client_secret or None,
        verify_ssl=req.verify_ssl,
    )

    def _connect():
        login = make_login(config)
        result = ApiPlatformCertificates.get_cert_trust_list(login, limit=1)
        if not isinstance(result, dict):
            raise ValueError(f"Unexpected response from ClearPass: {result!r}")
        return login

    try:
        login = await asyncio.to_thread(_connect)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Failed to connect to ClearPass: {exc}")

    _config = config
    _login = login
    return {"status": "ok", "server": config.server}


@app.get("/api/scan")
async def scan():
    """Fetch the full trust list and return only SHA-1 signed entries."""
    if not _login:
        raise HTTPException(400, "Not configured. POST /api/config first.")

    def _scan():
        entries = fetch_all_trust_list(_login)
        sha1 = identify_sha1_certs(_login, entries)
        return len(entries), sha1

    try:
        total, sha1_certs = await asyncio.to_thread(_scan)
    except Exception as exc:
        raise HTTPException(502, f"Scan failed: {exc}")

    return {
        "total_certs": total,
        "sha1_count": len(sha1_certs),
        "certs": [safe_serialize(c) for c in sha1_certs],
    }


@app.post("/api/certs/delete")
async def delete_certs(req: DeleteRequest):
    """Delete a list of trust list entries by ID."""
    if not _login:
        raise HTTPException(400, "Not configured.")

    def _delete_all():
        deleted, failed = [], []
        for cert_id in req.ids:
            try:
                remove_cert(_login, cert_id)
                deleted.append(cert_id)
            except Exception as exc:
                failed.append({"id": cert_id, "error": str(exc)})
        return deleted, failed

    deleted, failed = await asyncio.to_thread(_delete_all)
    return {"deleted": deleted, "failed": failed}


# ── Static files (index.html served at /) — must come last ────────────────────

app.mount("/", StaticFiles(directory="app/static", html=True), name="static")


# ── Auto-configure from env vars at startup ───────────────────────────────────

@app.on_event("startup")
async def _auto_configure():
    """If full credentials are present in env, configure automatically."""
    global _config, _login

    server = os.environ.get("CLEARPASS_SERVER", "").rstrip("/")
    api_token = os.environ.get("CLEARPASS_API_TOKEN")
    client_id = os.environ.get("CLEARPASS_CLIENT_ID")
    client_secret = os.environ.get("CLEARPASS_CLIENT_SECRET")
    verify_ssl = os.environ.get("CLEARPASS_VERIFY_SSL", "true").lower() not in ("false", "0", "no")

    if not server:
        return
    if not api_token and not (client_id and client_secret):
        return

    config = ClearPassConfig(
        server=server,
        api_token=api_token or None,
        client_id=client_id or None,
        client_secret=client_secret or None,
        verify_ssl=verify_ssl,
    )
    try:
        login = await asyncio.to_thread(make_login, config)
        _config = config
        _login = login
        print(f"[startup] Auto-configured for {server}")
    except Exception as exc:
        print(f"[startup] Auto-configuration failed: {exc}")
