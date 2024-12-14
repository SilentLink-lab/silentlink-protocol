from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from secrets import token_bytes
from typing import Dict, Optional

import ssl  # Ensure ssl module is imported and available

app = FastAPI()

# In-memory database simulation
keys_db: Dict[str, Dict] = {}
sessions_db: Dict[str, Dict] = {}

# Models for API requests and responses
class KeyPair(BaseModel):
    user_id: str
    public_key: str
    private_key: str

class EncryptRequest(BaseModel):
    user_id: str
    message: str

class EncryptResponse(BaseModel):
    nonce: str
    ciphertext: str

class DecryptRequest(BaseModel):
    user_id: str
    nonce: str
    ciphertext: str

class SessionRequest(BaseModel):
    user_1: str
    user_2: str

@app.post("/keys", response_model=KeyPair)
def generate_key_pair(user_id: str):
    """Generate and store a key pair for the user."""
    if user_id in keys_db:
        raise HTTPException(status_code=400, detail="User ID already exists.")

    private_key = token_bytes(32)
    public_key = token_bytes(32)  # Simplified for demonstration
    keys_db[user_id] = {
        "private_key": private_key,
        "public_key": public_key
    }

    return KeyPair(
        user_id=user_id,
        public_key=public_key.hex(),
        private_key=private_key.hex()
    )

@app.get("/keys/{user_id}", response_model=KeyPair)
def get_public_key(user_id: str):
    """Retrieve the public key of a user."""
    if user_id not in keys_db:
        raise HTTPException(status_code=404, detail="User ID not found.")

    user_keys = keys_db[user_id]
    return KeyPair(
        user_id=user_id,
        public_key=user_keys["public_key"].hex(),
        private_key=user_keys["private_key"].hex()
    )

@app.post("/encrypt", response_model=EncryptResponse)
def encrypt_message(request: EncryptRequest):
    """Encrypt a message using the user's private key."""
    if request.user_id not in keys_db:
        raise HTTPException(status_code=404, detail="User ID not found.")

    key = keys_db[request.user_id]["private_key"]
    nonce = token_bytes(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, request.message.encode(), None)

    return EncryptResponse(
        nonce=nonce.hex(),
        ciphertext=ciphertext.hex()
    )

@app.post("/decrypt")
def decrypt_message(request: DecryptRequest):
    """Decrypt a message using the user's private key."""
    if request.user_id not in keys_db:
        raise HTTPException(status_code=404, detail="User ID not found.")

    key = keys_db[request.user_id]["private_key"]
    cipher = ChaCha20Poly1305(key)
    nonce = bytes.fromhex(request.nonce)
    ciphertext = bytes.fromhex(request.ciphertext)

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    return {"plaintext": plaintext.decode()}

@app.post("/session/start")
def start_session(request: SessionRequest):
    """Start a session between two users."""
    if request.user_1 not in keys_db or request.user_2 not in keys_db:
        raise HTTPException(status_code=404, detail="One or both users not found.")

    session_id = f"{request.user_1}-{request.user_2}"
    shared_secret = token_bytes(32)  # Simplified for demonstration

    sessions_db[session_id] = {
        "user_1": request.user_1,
        "user_2": request.user_2,
        "shared_secret": shared_secret
    }

    return {"session_id": session_id, "shared_secret": shared_secret.hex()}

@app.post("/session/end")
def end_session(session_id: str):
    """End an active session."""
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found.")

    del sessions_db[session_id]
    return {"detail": "Session ended successfully."}
