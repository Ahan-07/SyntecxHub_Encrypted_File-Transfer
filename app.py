"""Flask API for authenticated uploads and downloads of encrypted files."""

from __future__ import annotations

import base64
import binascii
import functools
import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Callable

from flask import Flask, current_app, jsonify, render_template, request

from secure_storage import (
    CHUNK_SIZE,
    StorageError,
    cancel_upload,
    cleanup_stale_uploads,
    connect_database,
    create_upload,
    finalize_upload,
    get_completed_upload,
    get_upload,
    initialize_database,
    read_verified_chunk,
    store_encrypted_chunk,
    verify_manifest,
)


def decode_secret(value: str, name: str) -> bytes:
    """Decode and validate one base64-encoded 256-bit server secret."""
    try:
        secret = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError(f"{name} must be valid base64.") from error
    if len(secret) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes.")
    return secret


def _load_users() -> dict[str, str]:
    """Read the configured username-to-bearer-token mapping from the environment."""
    raw_users = os.environ.get("FILE_TRANSFER_USERS", "")
    if not raw_users.strip():
        raise RuntimeError(
            "FILE_TRANSFER_USERS is not set. Run the PowerShell setup commands "
            "in the same terminal before starting the server."
        )
    try:
        users = json.loads(raw_users)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "FILE_TRANSFER_USERS must contain a JSON object. In PowerShell, "
            "set it with: $env:FILE_TRANSFER_USERS = (@{ alice = $env:ALICE_TOKEN } "
            "| ConvertTo-Json -Compress)"
        ) from error
    if not isinstance(users, dict) or not users:
        raise RuntimeError("Set FILE_TRANSFER_USERS to a non-empty JSON object.")
    if any(
        not isinstance(username, str)
        or not username
        or not isinstance(token, str)
        or len(token) < 32
        for username, token in users.items()
    ):
        raise RuntimeError("Each user needs a name and a token of at least 32 characters.")
    return users


def create_app(test_config: dict | None = None) -> Flask:
    """Build the Flask application and apply safe defaults or test settings."""
    application = Flask(__name__, instance_relative_config=True)
    application.config.from_mapping(
        DATABASE_PATH=str(Path(application.instance_path) / "metadata.sqlite3"),
        STORAGE_PATH=str(Path(application.instance_path) / "encrypted_files"),
        MAX_CONTENT_LENGTH=CHUNK_SIZE + 12 + 16,
    )
    if test_config is None:
        application.config.update(
            USERS=_load_users(),
            AES_KEY=decode_secret(
                os.environ.get("FILE_TRANSFER_AES_KEY", ""), "FILE_TRANSFER_AES_KEY"
            ),
            HMAC_KEY=decode_secret(
                os.environ.get("FILE_TRANSFER_HMAC_KEY", ""),
                "FILE_TRANSFER_HMAC_KEY",
            ),
        )
    else:
        application.config.update(test_config)
    if secrets.compare_digest(
        application.config["AES_KEY"], application.config["HMAC_KEY"]
    ):
        raise RuntimeError("The AES key and HMAC key must be different secrets.")

    Path(application.config["STORAGE_PATH"]).mkdir(parents=True, exist_ok=True)
    with application.app_context():
        initialize_database()
        cleanup_stale_uploads()

    @application.errorhandler(StorageError)
    def handle_storage_error(error: StorageError):
        return jsonify({"error": str(error)}), 400

    @application.errorhandler(413)
    def handle_request_too_large(_error):
        return jsonify({"error": "The encrypted chunk is too large."}), 413

    def requires_authentication(function: Callable):
        """Check the bearer token and attach its configured owner to each request."""
        @functools.wraps(function)
        def wrapped_function(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                return jsonify({"error": "Authentication is required."}), 401
            supplied_token = authorization.removeprefix("Bearer ")
            for username, configured_token in current_app.config["USERS"].items():
                if secrets.compare_digest(supplied_token, configured_token):
                    request.environ["file_transfer_owner"] = username
                    return function(*args, **kwargs)
            return jsonify({"error": "Authentication failed."}), 401
        return wrapped_function

    @application.get("/")
    def home():
        return render_template("index.html")

    @application.get("/api/crypto-config")
    @requires_authentication
    def crypto_config():
        """Return the shared AES key only over the authenticated, same-origin API."""
        encoded_key = base64.b64encode(current_app.config["AES_KEY"]).decode("ascii")
        response = jsonify({"aes_key": encoded_key, "chunk_size": CHUNK_SIZE})
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.post("/api/uploads")
    @requires_authentication
    def begin_upload():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "Send a JSON upload description."}), 400
        upload = create_upload(
            request.environ["file_transfer_owner"],
            body.get("filename"),
            body.get("file_size"),
        )
        return jsonify(upload), 201

    @application.put("/api/uploads/<file_id>/chunks/<int:chunk_index>")
    @requires_authentication
    def upload_chunk(file_id: str, chunk_index: int):
        upload = get_upload(file_id, request.environ["file_transfer_owner"])
        if upload is None:
            return jsonify({"error": "The upload was not found."}), 404
        encrypted_record = request.get_data(cache=False)
        store_encrypted_chunk(upload, chunk_index, encrypted_record)
        return jsonify({"chunk_index": chunk_index, "accepted": True}), 201

    @application.post("/api/uploads/<file_id>/complete")
    @requires_authentication
    def complete_upload(file_id: str):
        upload = get_upload(file_id, request.environ["file_transfer_owner"])
        if upload is None:
            return jsonify({"error": "The upload was not found."}), 404
        finalize_upload(upload)
        return jsonify({"file_id": file_id, "integrity": "verified"}), 200

    @application.delete("/api/uploads/<file_id>")
    @requires_authentication
    def delete_incomplete_upload(file_id: str):
        upload = get_upload(file_id, request.environ["file_transfer_owner"])
        if upload is None:
            return jsonify({"error": "The upload was not found."}), 404
        cancel_upload(upload)
        return "", 204

    @application.get("/api/files")
    @requires_authentication
    def list_files():
        with connect_database() as connection:
            rows = connection.execute(
                """
                SELECT file_id, filename, file_size, created_at
                FROM uploads WHERE owner = ? AND state = 'complete'
                ORDER BY created_at DESC
                """,
                (request.environ["file_transfer_owner"],),
            ).fetchall()
        return jsonify(
            [
                {
                    "file_id": row["file_id"],
                    "filename": row["filename"],
                    "file_size": row["file_size"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        )

    @application.get("/api/files/<file_id>")
    @requires_authentication
    def file_manifest(file_id: str):
        upload = get_completed_upload(file_id, request.environ["file_transfer_owner"])
        if upload is None:
            return jsonify({"error": "The file was not found."}), 404
        verify_manifest(upload)
        return jsonify(
            {
                "file_id": upload["file_id"],
                "filename": upload["filename"],
                "file_size": upload["file_size"],
                "chunk_count": upload["chunk_count"],
                "chunk_size": CHUNK_SIZE,
                "integrity": "verified",
            }
        )

    @application.get("/api/files/<file_id>/chunks/<int:chunk_index>")
    @requires_authentication
    def download_chunk(file_id: str, chunk_index: int):
        upload = get_completed_upload(file_id, request.environ["file_transfer_owner"])
        if upload is None:
            return jsonify({"error": "The file was not found."}), 404
        encrypted_record = read_verified_chunk(upload, chunk_index)
        return current_app.response_class(
            encrypted_record,
            mimetype="application/octet-stream",
            headers={"X-Integrity-Verified": "true"},
        )

    return application


def run_local_server() -> None:
    """Run HTTPS when configured, or explicitly opt into loopback-only HTTP."""
    application = create_app()
    certificate = os.environ.get("FILE_TRANSFER_TLS_CERT")
    private_key = os.environ.get("FILE_TRANSFER_TLS_KEY")
    if bool(certificate) != bool(private_key):
        raise RuntimeError(
            "Set both FILE_TRANSFER_TLS_CERT and FILE_TRANSFER_TLS_KEY, or neither."
        )
    if certificate and private_key:
        application.run(
            host="0.0.0.0",
            port=5000,
            ssl_context=(certificate, private_key),
        )
    elif (
        os.environ.get("FILE_TRANSFER_ALLOW_LOOPBACK_HTTP") == "1"
        and os.environ.get("FILE_TRANSFER_HOST", "127.0.0.1") == "127.0.0.1"
    ):
        application.logger.warning(
            "Using HTTP on loopback only; this is for local development, not a secure network transfer."
        )
        application.run(host="127.0.0.1", port=5000)
    else:
        raise RuntimeError(
            "Configure FILE_TRANSFER_TLS_CERT and FILE_TRANSFER_TLS_KEY, "
            "or explicitly enable loopback-only development HTTP."
        )


if __name__ == "__main__":
    run_local_server()
