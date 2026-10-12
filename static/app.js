"use strict";

const tokenInput = document.querySelector("#access-token");
const fileInput = document.querySelector("#file-input");
const uploadButton = document.querySelector("#upload-button");
const refreshButton = document.querySelector("#refresh-button");
const fileList = document.querySelector("#file-list");
const progressBar = document.querySelector("#transfer-progress");
const statusMessage = document.querySelector("#status-message");
const textEncoder = new TextEncoder();
function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.dataset.state = isError ? "error" : "success";
}

function setBusy(isBusy) {
  uploadButton.disabled = isBusy;
  refreshButton.disabled = isBusy;
  tokenInput.disabled = isBusy;
  fileInput.disabled = isBusy;
  for (const button of fileList.querySelectorAll("button")) {
    button.disabled = isBusy;
  }
}

function getToken() {
  const token = tokenInput.value.trim();
  if (token.length < 32) {
    throw new Error("Enter the access token supplied by the server administrator.");
  }
  return token;
}

async function apiRequest(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${getToken()}`);
  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    let message = `The server returned HTTP ${response.status}.`;
    try {
      const errorBody = await response.json();
      if (typeof errorBody.error === "string") {
        message = errorBody.error;
      }
    } catch (error) {
      if (!(error instanceof SyntaxError)) {
        throw error;
      }
    }
    throw new Error(message);
  }
  return response;
}

async function getEncryptionKey(fileId) {
  const response = await apiRequest("/api/crypto-config");
  const settings = await response.json();
  const keyBytes = Uint8Array.from(
    atob(settings.aes_key),
    (character) => character.charCodeAt(0)
  );
  if (keyBytes.length !== 32) {
    throw new Error("The server supplied an invalid encryption key.");
  }
  const masterKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: textEncoder.encode(fileId),
      info: textEncoder.encode("encrypted-file-transfer/chunk-key/v1")
    },
    masterKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function makeAdditionalData(fileId, chunkIndex, chunkCount, fileSize) {
  return textEncoder.encode(`${fileId}:${chunkIndex}:${chunkCount}:${fileSize}`);
}

function joinEncryptedChunk(nonce, ciphertext) {
  const record = new Uint8Array(nonce.length + ciphertext.byteLength);
  record.set(nonce, 0);
  record.set(new Uint8Array(ciphertext), nonce.length);
  return record;
}

async function uploadFile() {
  const file = fileInput.files[0];
  if (!file) {
    throw new Error("Choose a file before uploading.");
  }
  if (file.size > 512 * 1024 * 1024) {
    throw new Error("The maximum file size is 512 MiB.");
  }

  const settingsResponse = await apiRequest("/api/crypto-config");
  const settings = await settingsResponse.json();
  const chunkSize = settings.chunk_size;
  const chunkCount = Math.ceil(file.size / chunkSize);
  const createResponse = await apiRequest("/api/uploads", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename: file.name, file_size: file.size })
  });
  const upload = await createResponse.json();

  try {
    const key = await getEncryptionKey(upload.file_id);
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
      const start = chunkIndex * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      const plaintext = await file.slice(start, end).arrayBuffer();
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: makeAdditionalData(
            upload.file_id, chunkIndex, chunkCount, file.size
          ),
          tagLength: 128
        },
        key,
        plaintext
      );
      const encryptedRecord = joinEncryptedChunk(nonce, ciphertext);
      await apiRequest(
        `/api/uploads/${encodeURIComponent(upload.file_id)}/chunks/${chunkIndex}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/octet-stream" },
          body: encryptedRecord
        }
      );
      progressBar.value = Math.round(((chunkIndex + 1) / chunkCount) * 100);
      setStatus(`Encrypted and uploaded chunk ${chunkIndex + 1} of ${chunkCount}.`);
    }

    const completeResponse = await apiRequest(
      `/api/uploads/${encodeURIComponent(upload.file_id)}/complete`,
      { method: "POST" }
    );
    await completeResponse.json();
    progressBar.value = 100;
    setStatus(`Upload complete. File integrity verified: ${upload.filename}`);
    await refreshFileList();
  } catch (error) {
    try {
      await apiRequest(`/api/uploads/${encodeURIComponent(upload.file_id)}`, {
        method: "DELETE"
      });
    } catch (cleanupError) {
      throw new Error(
        `${error.message} The incomplete upload could not be removed: ${cleanupError.message}`
      );
    }
    throw error;
  }
}

function formatFileSize(byteCount) {
  if (byteCount < 1024) {
    return `${byteCount} bytes`;
  }
  if (byteCount < 1024 * 1024) {
    return `${(byteCount / 1024).toFixed(1)} KiB`;
  }
  return `${(byteCount / (1024 * 1024)).toFixed(1)} MiB`;
}

async function refreshFileList() {
  const response = await apiRequest("/api/files");
  const files = await response.json();
  fileList.replaceChildren();
  for (const file of files) {
    const item = document.createElement("li");
    const downloadButton = document.createElement("button");
    downloadButton.type = "button";
    downloadButton.textContent = `Download ${file.filename} (${formatFileSize(file.file_size)})`;
    downloadButton.addEventListener("click", async () => {
      try {
        await downloadFile(file.file_id);
      } catch (error) {
        setStatus(error.message, true);
      }
    });
    item.append(downloadButton);
    fileList.append(item);
  }
  if (files.length === 0) {
    const emptyItem = document.createElement("li");
    emptyItem.textContent = "No completed files are stored for this account.";
    fileList.append(emptyItem);
  }
}

async function downloadFile(fileId) {
  setBusy(true);
  progressBar.value = 0;
  let writable;
  try {
    if (typeof window.showSaveFilePicker !== "function") {
      throw new Error(
        "This browser does not support safe chunked saving. Use a current version of Chrome or Edge."
      );
    }
    const manifestResponse = await apiRequest(
      `/api/files/${encodeURIComponent(fileId)}`
    );
    const manifest = await manifestResponse.json();
    const key = await getEncryptionKey(manifest.file_id);
    const destination = await window.showSaveFilePicker({
      suggestedName: manifest.filename
    });
    writable = await destination.createWritable();

    for (let chunkIndex = 0; chunkIndex < manifest.chunk_count; chunkIndex += 1) {
      const response = await apiRequest(
        `/api/files/${encodeURIComponent(fileId)}/chunks/${chunkIndex}`
      );
      if (response.headers.get("X-Integrity-Verified") !== "true") {
        throw new Error("The server did not confirm chunk integrity.");
      }
      const encryptedRecord = new Uint8Array(await response.arrayBuffer());
      if (encryptedRecord.length < 28) {
        throw new Error("A downloaded encrypted chunk is incomplete.");
      }
      const nonce = encryptedRecord.slice(0, 12);
      const ciphertext = encryptedRecord.slice(12);
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: makeAdditionalData(
            manifest.file_id,
            chunkIndex,
            manifest.chunk_count,
            manifest.file_size
          ),
          tagLength: 128
        },
        key,
        ciphertext
      );
      await writable.write(plaintext);
      progressBar.value = Math.round(
        ((chunkIndex + 1) / Math.max(manifest.chunk_count, 1)) * 100
      );
      setStatus(`Verified and decrypted chunk ${chunkIndex + 1} of ${manifest.chunk_count}.`);
    }

    await writable.close();
    writable = undefined;
    progressBar.value = 100;
    setStatus(`Download complete. Integrity verified: ${manifest.filename}`);
  } catch (error) {
    if (writable) {
      await writable.abort(error);
    }
    throw error;
  } finally {
    setBusy(false);
  }
}

uploadButton.addEventListener("click", async () => {
  setBusy(true);
  progressBar.value = 0;
  try {
    await uploadFile();
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setBusy(false);
  }
});

refreshButton.addEventListener("click", async () => {
  try {
    await refreshFileList();
    setStatus("Your authorized file list was refreshed.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

setStatus("Enter your access token to begin.");
