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

import paramiko
from flask import Flask, Response, request

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
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


def _check_auth() -> Response | None:
    """Return an error Response if the request is not properly authenticated,
    or ``None`` when authentication succeeds."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return Response("Missing Bearer token\n", status=401)
    token = header[len("Bearer "):]
    if token != Config.AUTH_TOKEN:
        return Response("Invalid token\n", status=403)
    return None


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


@app.route("/upload/<path:filename>", methods=["PUT"])
def upload(filename: str) -> Response:
    """Accept a file via HTTP PUT and upload it to the SFTP server.

    Usage::

        curl -X PUT \
             -H "Authorization: Bearer <token>" \
             --data-binary @localfile.txt \
             http://localhost:8080/upload/path/to/remote/file.txt
    """
    auth_err = _check_auth()
    if auth_err is not None:
        return auth_err

    data = request.get_data()
    if not data:
        return Response("Empty body\n", status=400)

    remote_path = f"{Config.SFTP_REMOTE_DIR.rstrip('/')}/{filename}"

    log.info("Uploading %d bytes -> %s", len(data), remote_path)
    try:
        _upload_to_sftp(data, remote_path)
    except Exception:
        log.exception("SFTP upload failed")
        return Response("SFTP upload failed\n", status=502)

    log.info("Upload complete: %s", remote_path)
    return Response("OK\n", status=201)


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _validate_config()
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
