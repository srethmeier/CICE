"""
HTTP PUT -> SFTP upload server.

Exposes a PUT endpoint that accepts a file and uploads it to a remote
SFTP server using SSH-key-based authentication.  The first path segment
of the URL selects which SFTP target to use, allowing different servers,
users and keys per base path.

Access to the endpoint is protected by a simple Bearer-token check.

Configuration is done via a JSON file – see ``targets.json.example``
or the ``_load_targets`` function below.
"""

import io
import json
import os
import stat
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass

import paramiko
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_TOKEN: str = os.environ.get("AUTH_TOKEN", "")
TARGETS_FILE: str = os.environ.get("TARGETS_FILE", "targets.json")


@dataclass(frozen=True)
class SFTPTarget:
    """Connection details for a single SFTP destination."""

    host: str
    port: int
    user: str
    key_path: str
    remote_dir: str


# name -> SFTPTarget, populated at startup
_targets: dict[str, SFTPTarget] = {}


def _load_targets(path: str) -> dict[str, SFTPTarget]:
    """Load SFTP target definitions from a JSON file.

    Expected format::

        {
            "backups": {
                "host": "backup.example.com",
                "port": 22,
                "user": "backupuser",
                "key_path": "/keys/backup_rsa",
                "remote_dir": "/data/backups"
            },
            "logs": {
                "host": "logs.example.com",
                "user": "logwriter",
                "key_path": "/keys/log_rsa",
                "remote_dir": "/var/incoming"
            }
        }

    ``port`` defaults to 22, ``remote_dir`` defaults to ``/upload``.
    """
    with open(path) as fh:
        raw = json.load(fh)

    targets: dict[str, SFTPTarget] = {}
    for name, cfg in raw.items():
        missing = [k for k in ("host", "user", "key_path") if k not in cfg]
        if missing:
            raise RuntimeError(
                f"Target '{name}' is missing required fields: {', '.join(missing)}"
            )
        targets[name] = SFTPTarget(
            host=cfg["host"],
            port=int(cfg.get("port", 22)),
            user=cfg["user"],
            key_path=cfg["key_path"],
            remote_dir=cfg.get("remote_dir", "/upload"),
        )
    return targets


def _validate_config() -> None:
    if not AUTH_TOKEN:
        raise RuntimeError("Required environment variable not set: AUTH_TOKEN")
    if not _targets:
        raise RuntimeError(
            f"No SFTP targets loaded – check {TARGETS_FILE}"
        )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

security = HTTPBearer()


@asynccontextmanager
async def lifespan(application: FastAPI):
    _targets.update(_load_targets(TARGETS_FILE))
    _validate_config()
    log.info("Loaded %d SFTP target(s): %s", len(_targets), ", ".join(_targets))
    yield


app = FastAPI(title="disp-api", lifespan=lifespan)


def _verify_token(credentials: HTTPAuthorizationCredentials) -> None:
    if credentials.credentials != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


def _ensure_remote_dir(sftp: paramiko.SFTPClient, path: str) -> None:
    """Recursively create *path* on the remote server if it doesn't exist."""
    parts = path.strip("/").split("/")
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            st = sftp.stat(current)
            if not stat.S_ISDIR(st.st_mode):
                raise RuntimeError(f"Remote path {current} exists but is not a directory")
        except FileNotFoundError:
            sftp.mkdir(current)


def _upload_to_sftp(target: SFTPTarget, data: bytes, remote_path: str) -> None:
    """Open an SFTP connection to *target* and write *data* to *remote_path*."""
    pkey = paramiko.RSAKey.from_private_key_file(target.key_path)

    transport = paramiko.Transport((target.host, target.port))
    try:
        transport.connect(username=target.user, pkey=pkey)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            remote_dir = os.path.dirname(remote_path)
            if remote_dir:
                _ensure_remote_dir(sftp, remote_dir)
            sftp.putfo(io.BytesIO(data), remote_path)
        finally:
            sftp.close()
    finally:
        transport.close()


@app.put("/{target_name}/{filename:path}", status_code=201, response_class=PlainTextResponse)
async def upload(
    target_name: str,
    filename: str,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Accept a file via HTTP PUT and upload it to the SFTP server.

    The first path segment selects the SFTP target (as defined in
    ``targets.json``).

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

    log.info("Uploading %d bytes -> %s@%s:%s", len(data), target.user, target.host, remote_path)
    try:
        _upload_to_sftp(target, data, remote_path)
    except Exception:
        log.exception("SFTP upload failed for target '%s'", target_name)
        raise HTTPException(status_code=502, detail="SFTP upload failed")

    log.info("Upload complete: %s@%s:%s", target.user, target.host, remote_path)
    return "OK\n"


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
