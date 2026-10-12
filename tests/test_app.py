import os
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import _load_users, create_app
from secure_storage import (
    CHUNK_SIZE,
    cleanup_stale_uploads,
    decrypt_file_chunk,
    encrypt_file_chunk,
    get_upload,
)


AES_KEY = bytes(range(32))
HMAC_KEY = bytes(reversed(range(32)))
TOKENS = {"alice": "a" * 40, "bob": "b" * 40}


@pytest.fixture
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "metadata.sqlite3"),
            "STORAGE_PATH": str(tmp_path / "encrypted"),
            "AES_KEY": AES_KEY,
            "HMAC_KEY": HMAC_KEY,
            "USERS": TOKENS,
        }
    )
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def headers(username="alice"):
    return {"Authorization": f"Bearer {TOKENS[username]}"}


def test_missing_user_configuration_has_actionable_error(monkeypatch):
    monkeypatch.delenv("FILE_TRANSFER_USERS", raising=False)
    with pytest.raises(RuntimeError, match="Run the PowerShell setup commands"):
        _load_users()


def test_user_configuration_reads_json_environment_value(monkeypatch):
    monkeypatch.setenv(
        "FILE_TRANSFER_USERS", json.dumps({"alice": TOKENS["alice"]})
    )
    assert _load_users() == {"alice": TOKENS["alice"]}


def begin(client, filename, content, username="alice"):
    response = client.post(
        "/api/uploads",
        json={"filename": filename, "file_size": len(content)},
        headers=headers(username),
    )
    assert response.status_code == 201
    return response.get_json()


def send_encrypted_chunks(client, upload, content, username="alice"):
    for chunk_index, start in enumerate(range(0, len(content), CHUNK_SIZE)):
        plaintext = content[start : start + CHUNK_SIZE]
        with client.application.app_context():
            row = get_upload(upload["file_id"], username)
            encrypted_record = encrypt_file_chunk(plaintext, row, chunk_index)
        response = client.put(
            f"/api/uploads/{upload['file_id']}/chunks/{chunk_index}",
            data=encrypted_record,
            headers=headers(username),
        )
        assert response.status_code == 201


def upload_complete(client, filename, content, username="alice"):
    upload = begin(client, filename, content, username)
    send_encrypted_chunks(client, upload, content, username)
    result = client.post(
        f"/api/uploads/{upload['file_id']}/complete",
        headers=headers(username),
    )
    assert result.status_code == 200
    return upload


def test_small_file_round_trip_and_encrypted_storage(client, app, tmp_path):
    original = b"hello, encrypted world"
    upload = upload_complete(client, "hello.txt", original)
    manifest = client.get(
        f"/api/files/{upload['file_id']}", headers=headers()
    )
    assert manifest.status_code == 200
    assert manifest.get_json()["integrity"] == "verified"

    response = client.get(
        f"/api/files/{upload['file_id']}/chunks/0", headers=headers()
    )
    assert response.status_code == 200
    with app.app_context():
        row = get_upload(upload["file_id"], "alice")
        recovered = decrypt_file_chunk(response.data, row, 0)
    assert recovered == original
    stored_bytes = (
        tmp_path / "encrypted" / upload["file_id"] / "00000000.chunk"
    ).read_bytes()
    assert original not in stored_bytes


def test_large_file_uses_separate_authenticated_chunks(client):
    original = os.urandom(CHUNK_SIZE * 2 + 19)
    upload = upload_complete(client, "large.bin", original)
    assert upload["chunk_count"] == 3
    restored = bytearray()
    for chunk_index in range(upload["chunk_count"]):
        response = client.get(
            f"/api/files/{upload['file_id']}/chunks/{chunk_index}",
            headers=headers(),
        )
        assert response.status_code == 200
        with client.application.app_context():
            row = get_upload(upload["file_id"], "alice")
            restored.extend(decrypt_file_chunk(response.data, row, chunk_index))
    assert bytes(restored) == original


def test_wrong_encryption_key_is_rejected(client, app):
    upload = begin(client, "wrong-key.bin", b"secret")
    with app.app_context():
        row = get_upload(upload["file_id"], "alice")
        nonce = b"n" * 12
        ciphertext = AESGCM(bytes([9]) * 32).encrypt(
            nonce, b"secret", f"{upload['file_id']}:0:1:6".encode()
        )
    response = client.put(
        f"/api/uploads/{upload['file_id']}/chunks/0",
        data=nonce + ciphertext,
        headers=headers(),
    )
    assert response.status_code == 400
    assert "authentication" in response.get_json()["error"]


def test_modified_ciphertext_is_rejected_on_upload(client):
    upload = begin(client, "tampered.bin", b"original")
    with client.application.app_context():
        row = get_upload(upload["file_id"], "alice")
        record = bytearray(encrypt_file_chunk(b"original", row, 0))
    record[-1] ^= 1
    response = client.put(
        f"/api/uploads/{upload['file_id']}/chunks/0",
        data=bytes(record),
        headers=headers(),
    )
    assert response.status_code == 400


def test_invalid_hmac_is_rejected_before_download(client, app):
    upload = upload_complete(client, "hmac.bin", b"authentic")
    with app.app_context():
        from secure_storage import connect_database

        with connect_database() as connection:
            connection.execute(
                "UPDATE chunks SET chunk_hmac = ? WHERE file_id = ?",
                (b"x" * 32, upload["file_id"]),
            )
    response = client.get(
        f"/api/files/{upload['file_id']}", headers=headers()
    )
    assert response.status_code == 400
    assert "manifest HMAC" in response.get_json()["error"]


def test_modified_stored_ciphertext_is_rejected_before_download(client, tmp_path):
    upload = upload_complete(client, "changed.bin", b"unchanged")
    chunk_path = (
        tmp_path / "encrypted" / upload["file_id"] / "00000000.chunk"
    )
    tampered_record = bytearray(chunk_path.read_bytes())
    tampered_record[-1] ^= 1
    chunk_path.write_bytes(tampered_record)
    response = client.get(
        f"/api/files/{upload['file_id']}/chunks/0", headers=headers()
    )
    assert response.status_code == 400
    assert "HMAC" in response.get_json()["error"]


def test_out_of_order_duplicate_and_missing_chunks_are_rejected(client):
    content = b"x" * (CHUNK_SIZE + 1)
    upload = begin(client, "ordered.bin", content)
    with client.application.app_context():
        row = get_upload(upload["file_id"], "alice")
        first_chunk = encrypt_file_chunk(content[:CHUNK_SIZE], row, 0)
        second_chunk = encrypt_file_chunk(content[CHUNK_SIZE:], row, 1)
    out_of_order = client.put(
        f"/api/uploads/{upload['file_id']}/chunks/1",
        data=second_chunk,
        headers=headers(),
    )
    assert out_of_order.status_code == 400
    accepted = client.put(
        f"/api/uploads/{upload['file_id']}/chunks/0",
        data=first_chunk,
        headers=headers(),
    )
    assert accepted.status_code == 201
    duplicate = client.put(
        f"/api/uploads/{upload['file_id']}/chunks/0",
        data=first_chunk,
        headers=headers(),
    )
    assert duplicate.status_code == 400
    incomplete = client.post(
        f"/api/uploads/{upload['file_id']}/complete",
        headers=headers(),
    )
    assert incomplete.status_code == 400


def test_path_traversal_filename_is_not_used_as_path(client, app, tmp_path):
    upload = upload_complete(client, r"..\..\private\file.txt", b"safe")
    assert upload["filename"] == "file.txt"
    assert list((tmp_path / "encrypted").iterdir()) == [
        tmp_path / "encrypted" / upload["file_id"]
    ]


def test_unauthorized_or_wrong_owner_cannot_download(client):
    upload = upload_complete(client, "private.txt", b"private")
    no_token = client.get(f"/api/files/{upload['file_id']}")
    wrong_owner = client.get(
        f"/api/files/{upload['file_id']}", headers=headers("bob")
    )
    assert no_token.status_code == 401
    assert wrong_owner.status_code == 404


def test_empty_file_is_completed_without_chunks(client):
    upload = upload_complete(client, "empty.txt", b"")
    assert upload["chunk_count"] == 0
    response = client.get(f"/api/files/{upload['file_id']}", headers=headers())
    assert response.status_code == 200
    assert response.get_json()["integrity"] == "verified"


def test_incomplete_upload_is_not_listed_and_can_be_removed(client, tmp_path):
    upload = begin(client, "unfinished.bin", b"not uploaded")
    listed = client.get("/api/files", headers=headers())
    assert listed.get_json() == []
    result = client.delete(
        f"/api/uploads/{upload['file_id']}", headers=headers()
    )
    assert result.status_code == 204
    assert not (tmp_path / "encrypted" / f".{upload['file_id']}.upload").exists()


def test_stale_incomplete_upload_is_cleaned_safely(app, tmp_path):
    client = app.test_client()
    upload = begin(client, "abandoned.bin", b"unfinished")
    with app.app_context():
        from secure_storage import connect_database

        with connect_database() as connection:
            connection.execute(
                """
                UPDATE uploads
                SET updated_at = datetime('now', '-2 days')
                WHERE file_id = ?
                """,
                (upload["file_id"],),
            )
        assert cleanup_stale_uploads() == 1
        assert get_upload(upload["file_id"], "alice") is None
    assert not (tmp_path / "encrypted" / f".{upload['file_id']}.upload").exists()


def test_encryption_round_trip_preserves_large_chunk_boundaries(app):
    content = os.urandom(CHUNK_SIZE + 7)
    with app.app_context():
        upload = begin(app.test_client(), "roundtrip.bin", content)
        row = get_upload(upload["file_id"], "alice")
        for chunk_index, start in enumerate(range(0, len(content), CHUNK_SIZE)):
            part = content[start : start + CHUNK_SIZE]
            encrypted = encrypt_file_chunk(part, row, chunk_index)
            assert decrypt_file_chunk(encrypted, row, chunk_index) == part
