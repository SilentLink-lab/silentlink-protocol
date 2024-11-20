# silentlink/utils.py

import os

def concat(*args):
    return b''.join(args)

def pad_message(message, block_size=256):
    padding_length = block_size - (len(message) % block_size)
    padding = os.urandom(padding_length)
    return message + padding

def unpad_message(padded_message, original_length=None):
    if original_length:
        return padded_message[:original_length]
    else:
        # Если длина оригинального сообщения неизвестна, нужно использовать схему паддинга с возможностью удаления
        # Например, PKCS#7 или добавить в конец сообщения длину паддинга
        pass
