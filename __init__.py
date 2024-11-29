# silentlink/__init__.py

"""
Пакет SilentLink — протокол безопасного обмена сообщениями.

Этот пакет включает модули для реализации клиента, криптографических примитивов и протоколов.
"""

from .crypto import (
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    encrypt,
    decrypt,
    hmac_sha256,
    verify_hmac,
    hkdf_extract_and_expand
)

from .protocol import Protocol, Session
from .user import User
from .utils import pad_message, unpad_message

# Определение публичного интерфейса пакета
__all__ = [
    'User',
    'Protocol',
    'Session',
    'generate_kyber_keypair',
    'kyber_encapsulate',
    'kyber_decapsulate',
    'encrypt',
    'decrypt',
    'hmac_sha256',
    'verify_hmac',
    'hkdf_extract_and_expand',
    'pad_message',
    'unpad_message'
]
