"""
HTTP PUT -> SFTPGo upload server.

Exposes a PUT endpoint that accepts a file and uploads it to a remote
SFTPGo server using its REST API.  The first path segment of the URL
selects which SFTPGo target to use, allowing different servers, users
and credentials per base path.

Access to the endpoint is protected by a simple Bearer-token check.

Configuration is done via the TARGETS_YAML environment variable – see
``targets.yaml.example`` or the ``_load_targets`` function below.
"""

import os
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import quote

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_TOKEN: str = os.environ.get("AUTH_TOKEN", "")
TARGETS_YAML: str = os.environ.get("TARGETS_YAML", "")


@dataclass(frozen=True)
class SFTPGoTarget:
    """Connection details for a single SFTPGo destination."""

    url: str
    user: str
    password: str
    remote_dir: str


# name -> SFTPGoTarget, populated at startup
_targets: dict[str, SFTPGoTarget] = {}


def _load_targets(raw_yaml: str) -> dict[str, SFTPGoTarget]:
    """Parse SFTPGo target definitions from a YAML string.

    Expected format::

        backups:
          url: https://sftpgo.example.com
          user: backupuser
          password: s3cret
          remote_dir: /data/backups
        logs:
          url: https://sftpgo-logs.example.com
          user: logwriter
          password: wr1t3r
          remote_dir: /var/incoming

    ``remote_dir`` defaults to ``/``.
    """
    raw = yaml.safe_load(raw_yaml)

    targets: dict[str, SFTPGoTarget] = {}
    for name, cfg in raw.items():
        missing = [k for k in ("url", "user", "password") if k not in cfg]
        if missing:
            raise RuntimeError(
                f"Target '{name}' is missing required fields: {', '.join(missing)}"
            )
        targets[name] = SFTPGoTarget(
            url=cfg["url"].rstrip("/"),
            user=cfg["user"],
            password=cfg["password"],
            remote_dir=cfg.get("remote_dir", "/"),
        )
    return targets


def _validate_config() -> None:
    if not AUTH_TOKEN:
        raise RuntimeError("Required environment variable not set: AUTH_TOKEN")
    if not TARGETS_YAML:
        raise RuntimeError("Required environment variable not set: TARGETS_YAML")
    if not _targets:
        raise RuntimeError("No SFTPGo targets loaded – check TARGETS_YAML")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SFTPGo REST API helpers
# ---------------------------------------------------------------------------


async def _get_sftpgo_token(client: httpx.AsyncClient, target: SFTPGoTarget) -> str:
    """Authenticate against the SFTPGo user token endpoint and return a JWT."""
    resp = await client.get(
        f"{target.url}/api/v2/user/token",
        auth=(target.user, target.password),
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"SFTPGo token request failed ({resp.status_code}): {resp.text}"
        )
    return resp.json()["access_token"]


async def _upload_to_sftpgo(target: SFTPGoTarget, data: bytes, remote_path: str) -> None:
    """Upload *data* to *remote_path* on the SFTPGo server via its REST API."""
    async with httpx.AsyncClient() as client:
        token = await _get_sftpgo_token(client, target)

        encoded_path = quote(remote_path, safe="/")
        upload_url = (
            f"{target.url}/api/v2/user/files/upload"
            f"?path={encoded_path}&mkdir_parents=true"
        )

        resp = await client.post(
            upload_url,
            headers={"Authorization": f"Bearer {token}"},
            content=data,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"SFTPGo upload failed ({resp.status_code}): {resp.text}"
            )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

security = HTTPBearer()


@asynccontextmanager
async def lifespan(application: FastAPI):
    _targets.update(_load_targets(TARGETS_YAML))
    _validate_config()
    log.info("Loaded %d SFTPGo target(s): %s", len(_targets), ", ".join(_targets))
    yield


app = FastAPI(title="disp-api", lifespan=lifespan)


def _verify_token(credentials: HTTPAuthorizationCredentials) -> None:
    if credentials.credentials != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


@app.put("/{target_name}/{filename:path}", status_code=201, response_class=PlainTextResponse)
async def upload(
    target_name: str,
    filename: str,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Accept a file via HTTP PUT and upload it to SFTPGo.

    The first path segment selects the SFTPGo target (as defined in
    the ``TARGETS_YAML`` env var).

    Usage::

        curl -X PUT \\
             -H "Authorization: Bearer <token>" \\
             --data-binary @localfile.txt \\
             http://localhost:8080/backups/path/to/remote/file.txt
    """
    _verify_token(credentials)

    target = _targets.get(target_name)
    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown target '{target_name}'. Available: {', '.join(sorted(_targets))}",
        )

    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="Empty body")

    remote_path = f"{target.remote_dir.rstrip('/')}/{filename}"

    log.info("Uploading %d bytes -> %s @ %s (%s)", len(data), remote_path, target.url, target.user)
    try:
        await _upload_to_sftpgo(target, data, remote_path)
    except Exception:
        log.exception("SFTPGo upload failed for target '%s'", target_name)
        raise HTTPException(status_code=502, detail="SFTPGo upload failed")

    log.info("Upload complete: %s @ %s", remote_path, target.url)
    return "OK\n"


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
