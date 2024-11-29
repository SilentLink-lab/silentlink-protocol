# crypto.py

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac

from pykyber import Kyber512  # Импортируем Kyber

def generate_kyber_keypair():
    """
    Генерирует пару ключей Kyber.

    Returns:
        tuple: (private_key, public_key)
    """
    kyber = Kyber512()
    public_key, private_key = kyber.keypair()
    return private_key, public_key

def kyber_encapsulate(public_key):
    """
    Выполняет инкапсуляцию сессии с использованием публичного ключа Kyber.

    Args:
        public_key (bytes): Публичный ключ Kyber.

    Returns:
        tuple: (ciphertext, shared_secret)
    """
    kyber = Kyber512()
    ciphertext, shared_secret = kyber.enc(public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(private_key, ciphertext):
    """
    Выполняет декапсуляцию сессии с использованием приватного ключа Kyber.

    Args:
        private_key (bytes): Приватный ключ Kyber.
        ciphertext (bytes): Инкапсулированный ключ.

    Returns:
        bytes: Shared secret.
    """
    kyber = Kyber512()
    shared_secret = kyber.dec(ciphertext, private_key)
    return shared_secret

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
        ciphertext (bytes): Нонс, объединенный с шифротекстом.

    Returns:
        bytes: Расшифрованные данные или None в случае ошибки.
    """
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aead = ChaCha20Poly1305(key)
    try:
        plaintext = aead.decrypt(nonce, ct, None)
        return plaintext
    except Exception:
        return None

def hmac_sha256(key, data):
    """
    Вычисляет HMAC-SHA256 от данных.

    Args:
        key (bytes): Ключ HMAC.
        data (bytes): Данные.

    Returns:
        bytes: HMAC.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(key, data, mac):
    """
    Проверяет HMAC-SHA256.

    Args:
        key (bytes): Ключ HMAC.
        data (bytes): Данные.
        mac (bytes): Ожидаемый HMAC.

    Returns:
        bool: True, если HMAC верен, иначе False.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(mac)
        return True
    except Exception:
        return False

def hkdf_extract_and_expand(salt, ikm, info, length=32):
    """
    Выполняет HKDF-Extract и HKDF-Expand.

    Args:
        salt (bytes): Соль.
        ikm (bytes): Исходный ключевой материал.
        info (bytes): Контекстная информация.
        length (int): Длина выходного ключа.

    Returns:
        bytes: Производный ключ.
    """
    # HKDF-Extract
    hkdf_extract = hmac_sha256(salt, ikm)

    # HKDF-Expand
    hkdf_expand = b''
    previous_block = b''
    counter = 1
    while len(hkdf_expand) < length:
        hmac_ctx = hmac.HMAC(hkdf_extract, hashes.SHA256())
        hmac_ctx.update(previous_block + info + bytes([counter]))
        previous_block = hmac_ctx.finalize()
        hkdf_expand += previous_block
        counter += 1

    return hkdf_expand[:length]
