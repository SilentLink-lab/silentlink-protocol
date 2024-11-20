# silentlink/crypto.py

from cryptography.hazmat.primitives.asymmetric import x25519
from pqcrypto.kem.kyber512 import generate_keypair as kyber_generate_keypair, encrypt as kyber_encrypt, decrypt as kyber_decrypt
from pqcrypto.sign.dilithium2 import generate_keypair as dilithium_generate_keypair, sign as dilithium_sign, verify as dilithium_verify
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_kyber_keypair():
    public_key, private_key = kyber_generate_keypair()
    return private_key, public_key

def generate_dilithium_keypair():
    private_key, public_key = dilithium_generate_keypair()
    return private_key, public_key

def hkdf_extract_and_expand(salt, input_key_material, info, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)

def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def encrypt(key, plaintext):
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt(key, ciphertext):
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ct, None)
    return plaintext

def generate_hmac(key, data):
    return hmac_sha256(key, data)

def verify_hmac(key, data, hmac_to_verify):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(hmac_to_verify)
        return True
    except:
        return False
