"""
HTTP PUT -> SFTP upload server.

Exposes a single PUT endpoint that accepts a file and uploads it to a
remote SFTP server using SSH-key-based authentication.  Access to the
endpoint is protected by a simple Bearer-token check.

Configuration is done entirely through environment variables – see
README or the ``Config`` class below for the full list.
"""

import io
import os
import stat
import logging
from contextlib import asynccontextmanager

import paramiko
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    """Read-once configuration from environment variables."""

    AUTH_TOKEN: str = os.environ.get("AUTH_TOKEN", "")

    SFTP_HOST: str = os.environ.get("SFTP_HOST", "localhost")
    SFTP_PORT: int = int(os.environ.get("SFTP_PORT", "22"))
    SFTP_USER: str = os.environ.get("SFTP_USER", "")
    SFTP_KEY_PATH: str = os.environ.get("SFTP_KEY_PATH", "")
    SFTP_REMOTE_DIR: str = os.environ.get("SFTP_REMOTE_DIR", "/upload")


def _validate_config() -> None:
    missing = []
    if not Config.AUTH_TOKEN:
        missing.append("AUTH_TOKEN")
    if not Config.SFTP_USER:
        missing.append("SFTP_USER")
    if not Config.SFTP_KEY_PATH:
        missing.append("SFTP_KEY_PATH")
    if missing:
        raise RuntimeError(
            f"Required environment variables not set: {', '.join(missing)}"
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
    _validate_config()
    yield


app = FastAPI(lifespan=lifespan)


def _verify_token(credentials: HTTPAuthorizationCredentials) -> None:
    if credentials.credentials != Config.AUTH_TOKEN:
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


def _upload_to_sftp(data: bytes, remote_path: str) -> None:
    """Open an SFTP connection and write *data* to *remote_path*."""
    pkey = paramiko.RSAKey.from_private_key_file(Config.SFTP_KEY_PATH)

    transport = paramiko.Transport((Config.SFTP_HOST, Config.SFTP_PORT))
    try:
        transport.connect(username=Config.SFTP_USER, pkey=pkey)
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


@app.put("/upload/{filename:path}", status_code=201, response_class=PlainTextResponse)
async def upload(
    filename: str,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Accept a file via HTTP PUT and upload it to the SFTP server.

    Usage::

        curl -X PUT \
             -H "Authorization: Bearer <token>" \
             --data-binary @localfile.txt \
             http://localhost:8080/upload/path/to/remote/file.txt
    """
    _verify_token(credentials)

    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="Empty body")

    remote_path = f"{Config.SFTP_REMOTE_DIR.rstrip('/')}/{filename}"

    log.info("Uploading %d bytes -> %s", len(data), remote_path)
    try:
        _upload_to_sftp(data, remote_path)
    except Exception:
        log.exception("SFTP upload failed")
        raise HTTPException(status_code=502, detail="SFTP upload failed")

    log.info("Upload complete: %s", remote_path)
    return "OK\n"


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
