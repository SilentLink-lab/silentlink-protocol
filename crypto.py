# crypto.py

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from pqcrypto.kem.kyber512 import (
    generate_keypair as kyber_generate_keypair,
    encrypt as kyber_encrypt,
    decrypt as kyber_decrypt
)
from pqcrypto.sign.dilithium2 import (
    generate_keypair as dilithium_generate_keypair,
    sign as dilithium_sign,
    verify as dilithium_verify
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag, InvalidSignature
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Инициализация ThreadPoolExecutor для асинхронных операций
executor = ThreadPoolExecutor(max_workers=4)

async def generate_x25519_keypair_async():
    """
    Асинхронная генерация пары ключей X25519.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, generate_x25519_keypair)

def generate_x25519_keypair():
    """
    Генерирует пару ключей X25519 для Диффи-Хеллмана.

    Returns:
        tuple: (private_key, public_key)
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_x25519_public_key(public_key):
    """
    Сериализует публичный ключ X25519 в байты.

    Args:
        public_key (x25519.X25519PublicKey): Публичный ключ.

    Returns:
        bytes: Сериализованный публичный ключ.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def deserialize_x25519_public_key(public_key_bytes):
    """
    Десериализует публичный ключ X25519 из байтов.

    Args:
        public_key_bytes (bytes): Байты публичного ключа.

    Returns:
        x25519.X25519PublicKey: Десериализованный публичный ключ.
    """
    return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

def generate_kyber_keypair():
    """
    Генерирует пару ключей Kyber512 для постквантового обмена ключами.

    Returns:
        tuple: (private_key, public_key)
    """
    public_key, private_key = kyber_generate_keypair()
    return private_key, public_key

def serialize_kyber_public_key(public_key):
    """
    Сериализует публичный ключ Kyber в байты.

    Args:
        public_key (bytes): Публичный ключ.

    Returns:
        bytes: Сериализованный публичный ключ.
    """
    return public_key

def deserialize_kyber_public_key(public_key_bytes):
    """
    Десериализует публичный ключ Kyber из байтов.

    Args:
        public_key_bytes (bytes): Байты публичного ключа.

    Returns:
        bytes: Десериализованный публичный ключ.
    """
    return public_key_bytes

def generate_dilithium_keypair():
    """
    Генерирует пару ключей Dilithium для постквантовых цифровых подписей.

    Returns:
        tuple: (private_key, public_key)
    """
    private_key, public_key = dilithium_generate_keypair()
    return private_key, public_key

def hkdf_extract_and_expand(salt, input_key_material, info, length=32):
    """
    Реализует HKDF для вывода ключей.

    Args:
        salt (bytes): Соль.
        input_key_material (bytes): Входной ключевой материал.
        info (bytes): Контекстная информация.
        length (int): Длина выводимого ключа.

    Returns:
        bytes: Выведенный ключ.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)

def hmac_sha256(key, data):
    """
    Вычисляет HMAC с использованием SHA-256.

    Args:
        key (bytes): Ключ для HMAC.
        data (bytes): Данные для аутентификации.

    Returns:
        bytes: HMAC-значение.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def encrypt(key, plaintext):
    """
    Шифрует данные с использованием ChaCha20-Poly1305.

    Args:
        key (bytes): 32-байтный ключ.
        plaintext (bytes): Данные для шифрования.

    Returns:
        bytes: Нонс, объединенный с шифротекстом.
    """
    nonce = os.urandom(12)  # 96-битный нонс
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt(key, ciphertext):
    """
    Расшифровывает данные, зашифрованные с помощью ChaCha20-Poly1305.

    Args:
        key (bytes): 32-байтный ключ.
        ciphertext (bytes): Нонс и шифротекст.

    Returns:
        bytes: Расшифрованные данные или None.
    """
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aead = ChaCha20Poly1305(key)
    try:
        plaintext = aead.decrypt(nonce, ct, None)
        return plaintext
    except InvalidTag:
        return None

def generate_hmac(key, data):
    """
    Генерирует HMAC для данных.

    Args:
        key (bytes): Ключ для HMAC.
        data (bytes): Данные для аутентификации.

    Returns:
        bytes: HMAC-значение.
    """
    return hmac_sha256(key, data)

def verify_hmac(key, data, hmac_to_verify):
    """
    Проверяет HMAC для данных.

    Args:
        key (bytes): Ключ для HMAC.
        data (bytes): Данные.
        hmac_to_verify (bytes): HMAC для проверки.

    Returns:
        bool: True, если HMAC корректен, иначе False.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(hmac_to_verify)
        return True
    except InvalidSignature:
        return False

def x25519_derive_shared_secret(private_key, peer_public_key_bytes):
    """
    Вычисляет общий секрет с помощью X25519.

    Args:
        private_key (x25519.X25519PrivateKey): Приватный ключ.
        peer_public_key_bytes (bytes): Публичный ключ получателя.

    Returns:
        bytes: Общий секрет.
    """
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(
        peer_public_key_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

def dilithium_sign_message(private_key, message):
    """
    Подписывает сообщение с использованием Dilithium.

    Args:
        private_key (bytes): Приватный ключ Dilithium.
        message (bytes): Сообщение для подписи.

    Returns:
        bytes: Цифровая подпись.
    """
    signature = dilithium_sign(private_key, message)
    return signature

def dilithium_verify_message(public_key, message, signature):
    """
    Проверяет подпись сообщения с использованием Dilithium.

    Args:
        public_key (bytes): Публичный ключ Dilithium.
        message (bytes): Подписанное сообщение.
        signature (bytes): Подпись.

    Returns:
        bool: True, если подпись корректна, иначе False.
    """
    try:
        dilithium_verify(public_key, message, signature)
        return True
    except:
        return False

def kyber_encrypt_message(public_key):
    """
    Шифрует сообщение с помощью Kyber.

    Args:
        public_key (bytes): Публичный ключ Kyber.

    Returns:
        tuple: (ciphertext, shared_secret)
    """
    ciphertext, shared_secret = kyber_encrypt(public_key)
    return ciphertext, shared_secret

def kyber_decrypt_message(private_key, ciphertext):
    """
    Расшифровывает сообщение с помощью Kyber.

    Args:
        private_key (bytes): Приватный ключ Kyber.
        ciphertext (bytes): Шифротекст.

    Returns:
        bytes: Общий секрет или None.
    """
    try:
        shared_secret = kyber_decrypt(private_key, ciphertext)
        return shared_secret
    except:
        return None
