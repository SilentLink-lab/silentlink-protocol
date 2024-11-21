# silentlink/utils.py

import os

def concat(*args):
    """
    Конкатенирует несколько байтовых строк в одну.

    Args:
        *args (bytes): Байтовые строки для конкатенации.

    Returns:
        bytes: Конкатенированная байтовая строка.
    """
    return b''.join(args)

def pad_message(message, block_size=256):
    """
    Дополняет сообщение паддингом в соответствии со схемой PKCS#7.

    Args:
        message (bytes): Исходное сообщение для паддинга.
        block_size (int): Размер блока. По умолчанию 256 байт.

    Returns:
        bytes: Сообщение с добавленным паддингом.
    """
    # Вычисляем количество байт паддинга, необходимых для выравнивания до размера блока
    padding_length = block_size - (len(message) % block_size)
    if padding_length == 0:
        padding_length = block_size  # Если сообщение уже кратно block_size, добавляем полный блок паддинга

    # Генерируем байты паддинга, каждый из которых равен padding_length
    padding = bytes([padding_length] * padding_length)

    # Возвращаем сообщение с добавленным паддингом
    return message + padding

def unpad_message(padded_message):
    """
    Удаляет паддинг из сообщения, дополненного по схеме PKCS#7.

    Args:
        padded_message (bytes): Сообщение с паддингом.

    Returns:
        bytes: Исходное сообщение без паддинга.

    Raises:
        ValueError: Если паддинг недействителен.
    """
    if not padded_message:
        raise ValueError("The padded message is empty")

    # Получаем значение последнего байта, которое указывает на длину паддинга
    padding_length = padded_message[-1]

    # Проверяем корректность длины паддинга
    if padding_length < 1 or padding_length > len(padded_message):
        raise ValueError("Invalid padding length")

    # Проверяем, что все байты паддинга имеют правильное значение
    if padded_message[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")

    # Возвращаем исходное сообщение без паддинга
    return padded_message[:-padding_length]
