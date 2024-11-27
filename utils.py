# utils.py

import os
import logging
from cryptography.hazmat.backends import default_backend

def concat(*args):
    """
    Конкатенирует несколько байтовых строк в одну.

    Args:
        *args (bytes): Байтовые строки.

    Returns:
        bytes: Конкатенированная строка.
    """
    return b''.join(args)

def pad_message(message, block_size=256):
    """
    Дополняет сообщение паддингом по схеме PKCS#7.

    Args:
        message (bytes): Исходное сообщение.
        block_size (int): Размер блока.

    Returns:
        bytes: Сообщение с паддингом.
    """
    padding_length = block_size - (len(message) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length] * padding_length)
    return message + padding

def unpad_message(padded_message):
    """
    Удаляет паддинг из сообщения.

    Args:
        padded_message (bytes): Сообщение с паддингом.

    Returns:
        bytes: Исходное сообщение.

    Raises:
        ValueError: Если паддинг недействителен.
    """
    if not padded_message:
        raise ValueError("The padded message is empty")

    padding_length = padded_message[-1]

    if padding_length < 1 or padding_length > len(padded_message):
        raise ValueError("Invalid padding length")

    if padded_message[-padding_length:] != bytes(
            [padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")

    return padded_message[:-padding_length]

def check_hardware_acceleration():
    """
    Проверяет, используется ли аппаратное ускорение в криптографии.
    """
    backend = default_backend()
    if backend.name == 'openssl':
        logging.info("Using OpenSSL backend for cryptography.")
        # Дополнительная проверка поддержки аппаратного ускорения
    else:
        logging.warning("No hardware acceleration backend available.")
