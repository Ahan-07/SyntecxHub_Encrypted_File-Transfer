"""Authenticated encryption and private, chunk-based file storage."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import struct
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app
from werkzeug.utils import secure_filename

CHUNK_SIZE = 1024 * 1024
MAX_FILE_SIZE = 512 * 1024 * 1024
NONCE_SIZE = 12
TAG_SIZE = 16


class StorageError(Exception):
    """A safe, expected storage or integrity error."""


def connect_database() -> sqlite3.Connection:
    """Open the SQLite database and make returned rows name-addressable."""
    connection = sqlite3.connect(current_app.config["DATABASE_PATH"])
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    """Create the upload table and per-chunk authentication records."""
    database_path = Path(current_app.config["DATABASE_PATH"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS uploads (
                file_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                state TEXT NOT NULL,
                manifest_hmac BLOB,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chunks (
                file_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_hmac BLOB NOT NULL,
                PRIMARY KEY (file_id, chunk_index),
                FOREIGN KEY (file_id) REFERENCES uploads(file_id)
            )
            """
        )
        upload_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(uploads)")
        }
        if "updated_at" not in upload_columns:
            connection.execute("ALTER TABLE uploads ADD COLUMN updated_at TEXT")
        connection.execute(
            "UPDATE uploads SET updated_at = created_at WHERE updated_at IS NULL"
        )


def create_upload(owner: str, filename: str, file_size: int) -> dict:
    """Create an empty, private staging directory and its database record."""
    if not isinstance(filename, str) or not filename.strip():
        raise StorageError("A filename is required.")
    if not isinstance(file_size, int) or isinstance(file_size, bool):
        raise StorageError("The file size must be an integer.")
    if file_size < 0 or file_size > MAX_FILE_SIZE:
        raise StorageError("The file must be no larger than 512 MiB.")

    basename = filename.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    clean_name = secure_filename(basename)
    if not clean_name:
        clean_name = "download"

    chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    file_id = str(uuid.uuid4())
    staging_path = Path(current_app.config["STORAGE_PATH"]) / f".{file_id}.upload"
    staging_path.mkdir(parents=True, exist_ok=False)
    try:
        with connect_database() as connection:
            connection.execute(
                """
                INSERT INTO uploads
                    (file_id, owner, filename, file_size, chunk_count, state, updated_at)
                VALUES (?, ?, ?, ?, ?, 'uploading', CURRENT_TIMESTAMP)
                """,
                (file_id, owner, clean_name, file_size, chunk_count),
            )
    except sqlite3.Error:
        staging_path.rmdir()
        raise

    return {
        "file_id": file_id,
        "filename": clean_name,
        "file_size": file_size,
        "chunk_count": chunk_count,
        "chunk_size": CHUNK_SIZE,
    }


def get_upload(file_id: str, owner: str) -> sqlite3.Row | None:
    """Return one upload only when it belongs to the authenticated owner."""
    with connect_database() as connection:
        return connection.execute(
            "SELECT * FROM uploads WHERE file_id = ? AND owner = ?",
            (file_id, owner),
        ).fetchone()


def get_completed_upload(file_id: str, owner: str) -> sqlite3.Row | None:
    """Return an owned upload only after it has been finalized."""
    with connect_database() as connection:
        return connection.execute(
            """
            SELECT * FROM uploads
            WHERE file_id = ? AND owner = ? AND state = 'complete'
            """,
            (file_id, owner),
        ).fetchone()


def chunk_aad(upload: sqlite3.Row, chunk_index: int) -> bytes:
    """Bind AES-GCM authentication to the file and expected chunk position."""
    return (
        f"{upload['file_id']}:{chunk_index}:{upload['chunk_count']}:"
        f"{upload['file_size']}"
    ).encode("utf-8")


def derive_file_encryption_key(upload: sqlite3.Row) -> bytes:
    """Derive an independent AES key for this server-created file identifier."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=upload["file_id"].encode("ascii"),
        info=b"encrypted-file-transfer/chunk-key/v1",
    ).derive(current_app.config["AES_KEY"])


def encrypt_file_chunk(
    plaintext: bytes, upload: sqlite3.Row, chunk_index: int
) -> bytes:
    """Encrypt one chunk and return its 12-byte nonce followed by ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    cipher = AESGCM(derive_file_encryption_key(upload))
    ciphertext = cipher.encrypt(
        nonce, plaintext, chunk_aad(upload, chunk_index)
    )
    return nonce + ciphertext


def decrypt_file_chunk(
    encrypted_record: bytes, upload: sqlite3.Row, chunk_index: int
) -> bytes:
    """Authenticate and decrypt one stored chunk, raising on any tampering."""
    if len(encrypted_record) < NONCE_SIZE + TAG_SIZE:
        raise StorageError("An encrypted chunk is incomplete.")
    nonce = encrypted_record[:NONCE_SIZE]
    ciphertext = encrypted_record[NONCE_SIZE:]
    try:
        return AESGCM(derive_file_encryption_key(upload)).decrypt(
            nonce, ciphertext, chunk_aad(upload, chunk_index)
        )
    except InvalidTag as error:
        raise StorageError("An encrypted chunk failed authentication.") from error


def calculate_chunk_hmac(
    upload: sqlite3.Row, chunk_index: int, encrypted_record: bytes
) -> bytes:
    """Authenticate a chunk's identity, position, size metadata, and bytes."""
    message = (
        chunk_aad(upload, chunk_index)
        + b":chunk:"
        + encrypted_record
    )
    return hmac.new(
        current_app.config["HMAC_KEY"], message, hashlib.sha256
    ).digest()


def calculate_manifest_hmac(upload: sqlite3.Row, chunk_tags: list[bytes]) -> bytes:
    """Authenticate the final ordered chunk list and completion state."""
    authenticator = hmac.new(
        current_app.config["HMAC_KEY"], digestmod=hashlib.sha256
    )
    authenticator.update(b"complete:")
    authenticator.update(upload["file_id"].encode("ascii"))
    authenticator.update(b":")
    authenticator.update(upload["filename"].encode("utf-8"))
    authenticator.update(struct.pack(">QQ", upload["file_size"], upload["chunk_count"]))
    for chunk_index, chunk_tag in enumerate(chunk_tags):
        authenticator.update(struct.pack(">Q", chunk_index))
        authenticator.update(chunk_tag)
    return authenticator.digest()


def encrypted_chunk_path(file_id: str, chunk_index: int, *, complete: bool) -> Path:
    """Build a storage path using only the validated UUID and numeric index."""
    root = Path(current_app.config["STORAGE_PATH"])
    folder_name = file_id if complete else f".{file_id}.upload"
    return root / folder_name / f"{chunk_index:08d}.chunk"


def store_encrypted_chunk(
    upload: sqlite3.Row, chunk_index: int, encrypted_record: bytes
) -> bytes:
    """Validate and persist one encrypted chunk, rejecting gaps and repeats."""
    if chunk_index < 0 or chunk_index >= upload["chunk_count"]:
        raise StorageError("This chunk number is outside the upload.")
    if len(encrypted_record) < NONCE_SIZE + TAG_SIZE:
        raise StorageError("The encrypted chunk is incomplete.")

    expected_size = min(
        CHUNK_SIZE, upload["file_size"] - chunk_index * CHUNK_SIZE
    )
    if len(encrypted_record) != NONCE_SIZE + expected_size + TAG_SIZE:
        raise StorageError("The encrypted chunk has an unexpected size.")

    with connect_database() as connection:
        latest = connection.execute(
            "SELECT COUNT(*) AS chunk_count FROM chunks WHERE file_id = ?",
            (upload["file_id"],),
        ).fetchone()["chunk_count"]
        if upload["state"] != "uploading" or chunk_index != latest:
            raise StorageError("Chunks must be uploaded once, in order.")

    decrypt_file_chunk(encrypted_record, upload, chunk_index)
    chunk_tag = calculate_chunk_hmac(upload, chunk_index, encrypted_record)
    chunk_path = encrypted_chunk_path(
        upload["file_id"], chunk_index, complete=False
    )
    with chunk_path.open("xb") as encrypted_file:
        encrypted_file.write(encrypted_record)
        encrypted_file.flush()
        os.fsync(encrypted_file.fileno())

    try:
        with connect_database() as connection:
            connection.execute(
                "INSERT INTO chunks (file_id, chunk_index, chunk_hmac) VALUES (?, ?, ?)",
                (upload["file_id"], chunk_index, chunk_tag),
            )
            connection.execute(
                "UPDATE uploads SET updated_at = CURRENT_TIMESTAMP WHERE file_id = ?",
                (upload["file_id"],),
            )
    except sqlite3.Error:
        chunk_path.unlink(missing_ok=True)
        raise
    return chunk_tag


def finalize_upload(upload: sqlite3.Row) -> None:
    """Verify every encrypted chunk, then atomically publish the upload."""
    if upload["state"] != "uploading":
        raise StorageError("This upload has already been finalized.")

    with connect_database() as connection:
        chunk_rows = connection.execute(
            """
            SELECT chunk_index, chunk_hmac FROM chunks
            WHERE file_id = ? ORDER BY chunk_index
            """,
            (upload["file_id"],),
        ).fetchall()
    if len(chunk_rows) != upload["chunk_count"]:
        raise StorageError("The upload is incomplete.")

    chunk_tags: list[bytes] = []
    for expected_index, chunk_row in enumerate(chunk_rows):
        if chunk_row["chunk_index"] != expected_index:
            raise StorageError("A chunk is missing or out of order.")
        encrypted_path = encrypted_chunk_path(
            upload["file_id"], expected_index, complete=False
        )
        try:
            encrypted_record = encrypted_path.read_bytes()
        except OSError as error:
            raise StorageError("An uploaded chunk is missing.") from error
        expected_tag = calculate_chunk_hmac(
            upload, expected_index, encrypted_record
        )
        if not hmac.compare_digest(expected_tag, chunk_row["chunk_hmac"]):
            raise StorageError("An uploaded chunk failed HMAC verification.")
        plaintext = decrypt_file_chunk(
            encrypted_record, upload, expected_index
        )
        expected_plaintext_size = min(
            CHUNK_SIZE, upload["file_size"] - expected_index * CHUNK_SIZE
        )
        if len(plaintext) != expected_plaintext_size:
            raise StorageError("An uploaded chunk has an invalid plaintext size.")
        chunk_tags.append(bytes(chunk_row["chunk_hmac"]))

    manifest_tag = calculate_manifest_hmac(upload, chunk_tags)
    staging_path = Path(current_app.config["STORAGE_PATH"]) / (
        f".{upload['file_id']}.upload"
    )
    final_path = Path(current_app.config["STORAGE_PATH"]) / upload["file_id"]
    os.replace(staging_path, final_path)
    with connect_database() as connection:
        connection.execute(
            """
            UPDATE uploads SET state = 'complete', manifest_hmac = ?
            WHERE file_id = ? AND state = 'uploading'
            """,
            (manifest_tag, upload["file_id"]),
        )


def verify_manifest(upload: sqlite3.Row) -> None:
    """Check the stored HMAC over the complete, ordered chunk-tag manifest."""
    with connect_database() as connection:
        chunk_rows = connection.execute(
            """
            SELECT chunk_index, chunk_hmac FROM chunks
            WHERE file_id = ? ORDER BY chunk_index
            """,
            (upload["file_id"],),
        ).fetchall()
    if len(chunk_rows) != upload["chunk_count"]:
        raise StorageError("The stored file is incomplete.")
    tags: list[bytes] = []
    for expected_index, row in enumerate(chunk_rows):
        if row["chunk_index"] != expected_index:
            raise StorageError("The stored file has missing or reordered chunks.")
        tags.append(bytes(row["chunk_hmac"]))
    expected_manifest = calculate_manifest_hmac(upload, tags)
    if not hmac.compare_digest(expected_manifest, upload["manifest_hmac"] or b""):
        raise StorageError("The stored file failed manifest HMAC verification.")


def read_verified_chunk(upload: sqlite3.Row, chunk_index: int) -> bytes:
    """Return one chunk only after its HMAC and AES-GCM tag have both passed."""
    if chunk_index < 0 or chunk_index >= upload["chunk_count"]:
        raise StorageError("This chunk number is outside the file.")
    with connect_database() as connection:
        row = connection.execute(
            """
            SELECT chunk_hmac FROM chunks
            WHERE file_id = ? AND chunk_index = ?
            """,
            (upload["file_id"], chunk_index),
        ).fetchone()
    if row is None:
        raise StorageError("A stored chunk is missing.")
    path = encrypted_chunk_path(upload["file_id"], chunk_index, complete=True)
    try:
        encrypted_record = path.read_bytes()
    except OSError as error:
        raise StorageError("A stored chunk is missing.") from error
    actual_tag = calculate_chunk_hmac(upload, chunk_index, encrypted_record)
    if not hmac.compare_digest(actual_tag, row["chunk_hmac"]):
        raise StorageError("A stored chunk failed HMAC verification.")
    decrypt_file_chunk(encrypted_record, upload, chunk_index)
    return encrypted_record


def cancel_upload(upload: sqlite3.Row) -> None:
    """Remove the private staging folder and its incomplete database records."""
    if upload["state"] != "uploading":
        raise StorageError("A completed file cannot be cancelled.")
    storage_root = Path(current_app.config["STORAGE_PATH"])
    possible_directories = [
        storage_root / f".{upload['file_id']}.upload",
        storage_root / upload["file_id"],
    ]
    for directory in possible_directories:
        if directory.exists():
            for child_path in directory.iterdir():
                if child_path.is_file():
                    child_path.unlink()
            directory.rmdir()
    with connect_database() as connection:
        connection.execute("DELETE FROM chunks WHERE file_id = ?", (upload["file_id"],))
        connection.execute("DELETE FROM uploads WHERE file_id = ?", (upload["file_id"],))


def cleanup_stale_uploads() -> int:
    """Remove interrupted staging uploads that have been idle for over 24 hours."""
    with connect_database() as connection:
        stale_uploads = connection.execute(
            """
            SELECT * FROM uploads
            WHERE state = 'uploading'
              AND COALESCE(updated_at, created_at) < datetime('now', '-24 hours')
            """
        ).fetchall()
    for upload in stale_uploads:
        cancel_upload(upload)
    return len(stale_uploads)
