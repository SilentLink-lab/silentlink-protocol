# utils.py

import os
import logging

def pad_message(message, block_size=1024):
    """
    Дополняет сообщение случайными данными до фиксированного размера.

    Args:
        message (bytes): Исходное сообщение.
        block_size (int): Фиксированный размер блока.

    Returns:
        bytes: Сообщение с паддингом.
    """
    if len(message) > block_size:
        raise ValueError("Message size exceeds block size")
    padding_length = block_size - len(message)
    padding = os.urandom(padding_length)
    return message + padding

def unpad_message(padded_message, original_message_length):
    """
    Удаляет паддинг из сообщения.

    Args:
        padded_message (bytes): Сообщение с паддингом.
        original_message_length (int): Оригинальная длина сообщения.

    Returns:
        bytes: Исходное сообщение.
    """
    return padded_message[:original_message_length]

def concat(*args):
    """
    Конкатенирует несколько байтовых строк в одну.

    Args:
        *args (bytes): Байтовые строки.

    Returns:
        bytes: Конкатенированная строка.
    """
    return b''.join(args)

def check_hardware_acceleration():
    """
    Проверяет, используются ли аппаратные ускорения для криптографии.

    Returns:
        bool: True, если аппаратное ускорение доступно, иначе False.
    """
    try:
        # Проверяем наличие аппаратного ускорения для AES-NI
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend._lib.Cryptography_HAS_AESNI() == 1
    except AttributeError:
        return False

def serialize_public_key(public_key):
    """
    Сериализует публичный ключ в строку в формате PEM.

    Args:
        public_key: Публичный ключ.

    Returns:
        str: Строка с публичным ключом в формате PEM.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def deserialize_public_key(pem_str):
    """
    Десериализует публичный ключ из строки в формате PEM.

    Args:
        pem_str (str): Строка с публичным ключом в формате PEM.

    Returns:
        Публичный ключ.
    """
    pem_bytes = pem_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(pem_bytes)
    return public_key

def generate_random_padding(min_length=0, max_length=256):
    """
    Генерирует случайный паддинг заданной длины.

    Args:
        min_length (int): Минимальная длина паддинга.
        max_length (int): Максимальная длина паддинга.

    Returns:
        bytes: Случайный паддинг.
    """
    padding_length = os.urandom(1)[0] % (max_length - min_length + 1) + min_length
    return os.urandom(padding_length)

def get_current_timestamp():
    """
    Возвращает текущую метку времени.

    Returns:
        int: Текущее время в секундах с начала эпохи.
    """
    return int(time.time())
