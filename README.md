# Encrypted File Transfer & Secure File Storage

This is a small learning application: the browser encrypts file chunks with
AES-256-GCM, Flask accepts and stores only encrypted chunks, and the browser
decrypts each chunk after an authorized download. The files and SQLite database
live in Flask's private `instance` directory, not its public `static` directory.

## Phase 1 — Architecture in plain English

1. A user enters a bearer token that the server administrator configured.
2. The browser asks the authenticated server for the shared AES master key over
   the same-origin connection. It keeps that key in memory only.
3. The server creates a random UUID and records the owner, safe display name,
   size, and expected number of chunks in SQLite.
4. The browser derives a per-file AES key, reads at most 1 MiB from the selected
   file, encrypts that piece, and uploads its nonce and ciphertext. It repeats
   this for each piece.
5. The server checks each AES-GCM tag, calculates an HMAC-SHA-256 for each
   encrypted chunk, and writes the encrypted record to a private staging
   directory. It rejects skipped, repeated, and incorrectly sized chunks.
6. Finalization checks that every expected chunk exists and authenticates. The
   server calculates a final HMAC over the file ID, safe filename, file size,
   completion marker, and ordered chunk tags, then publishes the staged folder.
7. For download, the server checks the final HMAC before returning a manifest.
   It checks each chunk's HMAC and AES-GCM tag before returning that ciphertext.
   The browser checks AES-GCM again and streams the plaintext to a save dialog.

**Encryption at rest** protects saved bytes if someone obtains only the storage
folder. **Encryption in transit** protects traffic while it travels over the
network. **File encryption** is the AES-GCM operation performed in the browser.
AES does not make plain HTTP safe: an attacker on the network could steal the
bearer token or replace application code. Use valid, correctly checked HTTPS
certificates for any network deployment.

### Cryptography, simply

- **AES** is a well-studied cipher. AES-256 uses a 256-bit secret key.
- A **symmetric key** is the same secret used to encrypt and decrypt. Anyone
  who gets this project's master key can decrypt its stored files.
- A **nonce** is a per-encryption-use value, not a password. AES-GCM needs a
  fresh 12-byte nonce for every chunk encrypted with the same key. The browser
  generates a random nonce for each chunk; a server-created file ID is also
  used with HKDF to derive a distinct AES key for each file.
- **Authenticated encryption** means AES-GCM checks both confidentiality and
  authenticity. A changed ciphertext, nonce, or associated-data value causes
  decryption to fail before plaintext is returned.
- A **hash** is a fixed-size fingerprint. Plain SHA-256 can notice changes but
  cannot prove who made the fingerprint. **HMAC-SHA-256** combines a secret
  key with a message, so an attacker with storage but without the HMAC key
  cannot create a valid tag. HMAC comparisons use Python's
  `hmac.compare_digest`, which avoids leaking how many leading bytes matched.
- AES-GCM authenticates each chunk independently. The separate HMAC is useful
  here because it authenticates the stored chunk records and the final ordered
  manifest, including the file ID and finalization state. This design does not
  pretend one whole-file HMAC can verify a chunk independently: each chunk has
  its own HMAC, and the final HMAC authenticates the ordered list of those tags.
  The HMAC key is separately generated and never sent to the browser.

The AES key is also held by the server and is returned to authenticated
browsers. All configured accounts share it. This keeps the teaching project
small, but a malicious authorized user could decrypt ciphertext they obtain.
Use per-user/per-file key management and a proper identity provider for a
multi-user production service.

## Phase 2 — Files and dependencies

| File | Purpose and connections |
| --- | --- |
| `app.py` | Flask app factory, environment configuration, bearer authentication, API routes, and local HTTPS/loopback startup. Calls storage functions and renders the page. |
| `secure_storage.py` | SQLite metadata, private chunk files, HKDF, AES-GCM, per-chunk HMAC, manifest HMAC, and safe finalization. Called by `app.py`; no browser/UI logic. |
| `templates/index.html` | Small accessible page with token, file picker, file list, status, and progress. Loads the files under `static/`. |
| `static/app.js` | Browser requests, chunking, Web Crypto, upload/download progress, and safe saving. It does not construct HTML from untrusted filename markup. |
| `static/style.css` | Responsive neutral styling only. |
| `tests/test_app.py` | Tests crypto, upload/download routes, authorization, corruption, chunk order, path safety, and empty/incomplete files. |
| `requirements.txt` | Flask, `cryptography`, and pytest dependencies. |
| `.gitignore` | Excludes the virtual environment, Python caches, and private `instance/` data. |

Install only the listed Python packages. The browser's built-in Web Crypto API
performs client-side AES-GCM; Python `cryptography` independently validates
those authenticated records on the server.

## Phases 3–6 — Encryption, integrity, storage, and API

The important storage functions are intentionally small:

- `derive_file_encryption_key()` uses HKDF-SHA-256, the master AES key, and a
  server-generated file ID. HKDF is a standard key-derivation function; the
  browser uses the same inputs and label.
- `chunk_aad()` creates AES-GCM associated data from the file ID, chunk index,
  total chunk count, and original byte size. AAD is authenticated but not
  encrypted.
- `encrypt_file_chunk()` and `decrypt_file_chunk()` use the library's
  `AESGCM`, never a home-made cipher. Decryption raises a safe `StorageError`
  when its tag is invalid.
- `calculate_chunk_hmac()` binds each ciphertext to its file and position.
  `calculate_manifest_hmac()` binds all ordered chunk tags and completion
  metadata. `verify_manifest()` checks this final value before a download.
- `store_encrypted_chunk()` enforces exact chunk sizes and sequential,
  one-time uploads. `finalize_upload()` refuses incomplete uploads and only
  makes the folder visible after checks pass.
- `cleanup_stale_uploads()` removes interrupted uploads older than 24 hours
  when the server starts. `cancel_upload()` removes only that upload's
  server-generated storage paths and metadata.
- `read_verified_chunk()` checks both HMAC and AES-GCM before returning the
  encrypted bytes. The browser decrypts only after receiving a successful
  response.
- `create_app()` wires configuration and routes. `requires_authentication()`
  checks the bearer token on every API route. A file lookup includes the
  authenticated owner, so an account cannot retrieve another owner's file.

Python type annotations describe expected input/output types; they do not
convert or validate values by themselves. SQLite's `?` placeholders keep
client data separate from SQL syntax. `with` blocks close database/file
resources even when an error is raised. Flask decorators register URL routes
and wrap protected handlers with authentication.

The complete implementations are in `secure_storage.py` and `app.py`. The
browser's `uploadFile()` and `downloadFile()` are the transfer loops: each
iteration processes exactly one bounded chunk. `makeAdditionalData()` must
match the Python `chunk_aad()` format byte for byte.

### Function and syntax guide

In `app.py`, `decode_secret(value, name)` turns a base64 string into 32 bytes
or raises a configuration error. `_load_users()` returns a dictionary from
user name to token. `create_app(test_config)` returns a Flask application;
`test_config` is optional and lets tests provide temporary keys, users, and
paths without environment secrets. `run_local_server()` checks TLS settings
before starting the development server.

Its routes accept JSON metadata, raw encrypted chunk bytes, or an ID/index in
the URL. The protected handlers are:

| Route function | Input and result |
| --- | --- |
| `crypto_config()` | Authenticated `GET`; returns the AES key and chunk size with `Cache-Control: no-store`. |
| `begin_upload()` | Authenticated JSON filename/size; returns the server UUID and chunk plan. |
| `upload_chunk(file_id, chunk_index)` | Authenticated binary `PUT`; returns 201 only for the next valid chunk. |
| `complete_upload(file_id)` | Authenticated `POST`; rejects incomplete or corrupt uploads. |
| `delete_incomplete_upload(file_id)` | Authenticated `DELETE`; removes only that owner's unfinished upload. |
| `list_files()` | Returns completed records belonging to the authenticated user. |
| `file_manifest(file_id)` | Checks final HMAC before returning safe download metadata. |
| `download_chunk(file_id, chunk_index)` | Checks HMAC and AES-GCM before returning encrypted bytes. |

In `secure_storage.py`, the data types are visible in signatures: `bytes` are
file/key data, `str` is metadata/IDs, `int` is a size/index, `Path` is a
filesystem location, and `sqlite3.Row` is one database record. Functions
return `None` when a lookup is absent or an operation succeeds without a
value; `create_upload()` returns a small dictionary of upload metadata.
`StorageError` is the expected, safe-to-show failure type; invalid AES-GCM tags
are converted into that error. Database and filesystem errors are not
silently treated as success.

`connect_database()` and the file `open()` calls use `with` context managers:
Python closes those resources when the indented block ends. `@application.get`
and the other route decorators register a URL. The nested
`@requires_authentication` decorator checks the bearer token before the route
body runs. `try`/`except` is used only to turn an invalid authentication tag
or missing stored chunk into a clear application error, or to remove a file
after a failed database insert before re-raising that database error.

In `static/app.js`, `setStatus()` changes accessible user feedback;
`setBusy()` disables controls during a transfer; `getToken()` validates that
the user entered a token; `apiRequest()` adds the bearer header and turns an
HTTP error into a visible message; `getEncryptionKey(fileId)` imports the
master bytes and derives a file-specific non-exportable Web Crypto key.
`makeAdditionalData()` matches the server's associated-data string.
`joinEncryptedChunk()` joins nonce and ciphertext into one request body.
`uploadFile()` and `downloadFile()` each loop over one chunk at a time.
`formatFileSize()` is display-only, and `refreshFileList()` safely creates
buttons using DOM APIs. `async`/`await` lets a readable function wait for
network and crypto operations without blocking the page; `try`/`finally`
restores controls even when a transfer fails.

The HTML's `label` elements name the controls for screen readers. The
`aria-live` status and progress elements announce transfer changes. CSS
variables and media rules keep the layout readable on small screens; no
security behavior is implemented in CSS.

## Phase 7 — Interface

The HTML has only the required controls. The JavaScript uses `textContent` and
DOM element creation for returned filenames, rather than interpreting a
filename as HTML. Progress advances after each successfully transferred
chunk. Downloads use the browser File System Access API so a large file is
written incrementally instead of collected into one large in-memory Blob.
Use a current Chrome or Edge browser for downloads; unsupported browsers get a
clear message instead of silently loading a large file into memory.

The browser asks for a destination filename using the server-sanitized display
name. The user confirms the location in the browser's save dialog. Server
storage paths are never sent to the browser.

## Phase 8 — Authentication and authorization

This learning version uses configured bearer tokens, not passwords or cookies.
Each account has a username and a random token of at least 32 characters.
Tokens and encryption keys belong in protected environment configuration, not
in source files or logs. The SQLite `owner` field and owner-filtered queries
enforce file ownership. A missing/invalid token gets HTTP 401; another user's
file is reported as not found.

## Phase 9 — Install, run, and test (Windows PowerShell)

Use Python 3.10 or newer. Check the installed version in PowerShell:

```powershell
py --version
py -3 -c "import sys; print(sys.version)"
```

Then run these commands from the project directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal
only, then activate again. Alternatively run `.venv\Scripts\python.exe`
directly.

Create independent development keys and an example user's token for the
current PowerShell session. **Run this setup block and `python app.py` in the
same PowerShell window**: `$env:` variables are process/session-local and
won't be present in a new terminal window.

```powershell
$env:FILE_TRANSFER_AES_KEY = python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
$env:FILE_TRANSFER_HMAC_KEY = python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
$env:ALICE_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:FILE_TRANSFER_USERS = (@{ alice = $env:ALICE_TOKEN } | ConvertTo-Json -Compress)
$env:FILE_TRANSFER_ALLOW_LOOPBACK_HTTP = "1"
```

Keep the same AES and HMAC keys when restarting if you need to read existing
files. Regenerating the AES key makes existing data undecryptable; regenerating
the HMAC key makes existing tags unverifiable. Back up production secrets
securely and plan key rotation before changing them. These example values are
temporary development secrets, not production credentials.

Start the local-only development server:

```powershell
python app.py
```

If the server reports that `FILE_TRANSFER_USERS` is not set, the setup block
was not run in this terminal, or this is a newly opened PowerShell window.
Return to the project folder in that window and run the setup block first.
You can confirm the values are present without printing the secrets:

```powershell
@("FILE_TRANSFER_AES_KEY", "FILE_TRANSFER_HMAC_KEY", "FILE_TRANSFER_USERS") |
  ForEach-Object { "{0} configured: {1}" -f $_, [bool](Get-Item "Env:$_" -ErrorAction SilentlyContinue) }
```

Do not regenerate keys after uploading files: the old files require the same
AES and HMAC keys. For now, keep the PowerShell window with those values open
while using the project. If you close it, preserve the keys securely and set
the same values again before restarting.

Expected startup includes a warning that HTTP is enabled on loopback only.
Open `http://127.0.0.1:5000`, enter the printed value of `$env:ALICE_TOKEN`
(retrieve it with `Write-Output $env:ALICE_TOKEN`), select a test file, and
upload it. Loopback HTTP is a deliberate local-development exception; it is
not safe for a shared network. The browser treats localhost as a secure
context for Web Crypto and the file-save API.

Check server storage in another PowerShell window:

```powershell
Get-ChildItem .\instance\encrypted_files -Recurse
```

The chunk files contain a 12-byte nonce followed by AES-GCM ciphertext and its
16-byte authentication tag. They should not contain the original file bytes.
The SQLite database contains ownership and integrity metadata, not plaintext
file contents or encryption keys.

Download from the page and compare the two files:

```powershell
Get-FileHash .\sample.txt -Algorithm SHA256
Get-FileHash "$env:USERPROFILE\Downloads\sample.txt" -Algorithm SHA256
```

Matching SHA-256 values show the downloaded bytes match this test source file.
This comparison is a learning check, not the authentication mechanism; AES-GCM
and HMAC provide the app's cryptographic integrity checks.

Run all automated tests:

```powershell
python -m pytest -v
```

Expected result: **15 passed**. A failure means the corresponding behavior
needs investigation; do not use confidential files or production keys in
tests. The tests cover small and multi-chunk round trips, invalid keys and
modified data, invalid HMAC, ordering/duplicates/missing chunks, incomplete
uploads, ownership, traversal-safe filenames, encrypted stored bytes, and
empty files.

### Linux/macOS equivalents

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export FILE_TRANSFER_AES_KEY="$(python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
export FILE_TRANSFER_HMAC_KEY="$(python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
export ALICE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export FILE_TRANSFER_USERS="{\"alice\":\"$ALICE_TOKEN\"}"
export FILE_TRANSFER_ALLOW_LOOPBACK_HTTP=1
python app.py
python -m pytest -v
```

Do not put real keys or tokens in shell scripts committed to Git. Supply stable
secrets through a protected secret manager or service environment.

## Phase 10 — Threat model and deployment

- **Man-in-the-middle:** A network attacker could observe or change unprotected
  traffic, steal tokens, or replace browser JavaScript. Production must use
  HTTPS with a valid certificate and normal certificate validation. Never
  disable certificate checks. The development HTTP exception binds only to
  `127.0.0.1`.
- **Stolen storage:** Chunk files alone do not reveal file contents without the
  AES key. The key and the independently generated HMAC key are environment
  secrets, outside `instance/encrypted_files`. Restrict host access and back up
  secrets separately from encrypted data.
- **Modified files:** AES-GCM checks each encrypted chunk; separate keyed
  per-chunk HMACs and a final manifest HMAC check the stored bytes, order,
  identity, metadata, and completion. Invalid content is rejected before it
  is returned.
- **Unauthorized downloads:** Every API route checks a bearer token, and
  database queries are constrained to that token's owner. IDs are random
  server-generated UUIDs, never filesystem paths.
- **Path traversal:** A submitted name is reduced to a display-only basename;
  storage paths are built from generated IDs and integer chunk positions.
- **Leaked keys:** Keys/tokens are not source code or logs. Environment
  variables are convenient for development but may be visible to privileged
  processes; use a secrets manager in production. Back up keys securely and
  define a tested rotation/re-encryption process.
- **Replay, reordering, and duplicates:** Uploads accept exactly the next
  expected index once. Authenticated data includes file ID, index, total
  chunks, and total size. Finalization rejects missing pieces and the manifest
  HMAC binds the ordered list and completion marker.

Encryption cannot stop someone from deleting files, denying service, or
misusing plaintext after an authorized user downloads it. The server also
holds the shared AES master key and authorized browsers receive it, so a fully
compromised server or malicious authorized account can access content.

Flask's built-in server is for local development only. For production, use a
production WSGI server behind a correctly configured HTTPS reverse proxy,
trusted certificates, secure secret storage, account/token provisioning and
revocation, backups, monitoring, request limits, and operational key rotation.
Set `FILE_TRANSFER_TLS_CERT` and `FILE_TRANSFER_TLS_KEY` together to use the
built-in HTTPS mode for a trusted development certificate; it still does not
turn Flask's development server into a production server.

## Common errors

- **Missing environment configuration:** Set both keys and a non-empty users
  JSON mapping before starting. Keys must be base64 encodings of 32 random
  bytes; user tokens must be at least 32 characters.
- **HTTP startup refused:** Configure both TLS certificate paths, or explicitly
  set `FILE_TRANSFER_ALLOW_LOOPBACK_HTTP=1` while using `127.0.0.1` for local
  development only.
- **HTTP 401:** Check the token against the configured user mapping.
- **Authentication failed / corrupt chunk:** Do not retry by disabling
  verification. Cancel the incomplete upload, check that client and server
  retain the same key, and start a fresh upload. Interrupted uploads are
  removed at server startup after being idle for more than 24 hours.
- **Download reports missing/incomplete data:** The upload was not finalized,
  or storage has been modified. Do not treat it as a successful download.
- **PowerShell activation denied:** Use the process-scoped execution-policy
  command above or invoke `.venv\Scripts\python.exe` without activation.
