# protocol.py

import json
import asyncio
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import (
    generate_x25519_keypair,
    serialize_x25519_public_key,
    x25519_derive_shared_secret,
    encrypt,
    decrypt,
    hmac_sha256,
    verify_hmac
)
from .utils import pad_message, unpad_message

class Session:
    def __init__(self):
        """
        Инициализирует сессию для обмена сообщениями.
        """
        self.root_key = None
        self.send_chain_key = None
        self.receive_chain_key = None

        self.dh_send_private = None
        self.dh_send_public = None
        self.dh_receive_public = None

        self.send_message_index = 0
        self.receive_message_index = 0

        self.previous_receive_chain_keys = {}
        self.message_keys = {}  # Хранение ключей сообщений

        self.received_message_indices = set()

class Protocol:
    def __init__(self, user):
        """
        Инициализирует протокол для пользователя.

        Args:
            user (User): Объект пользователя.
        """
        self.user = user

    async def initialize_session(self, recipient_username):
        """
        Инициализирует сессию с получателем.

        Args:
            recipient_username (str): Имя получателя.
        """
        recipient_info = await self.user.get_recipient_info(recipient_username)
        if recipient_info is None:
            raise Exception("Recipient information not available")

        session = Session()

        # Генерация эфемерных ключей
        session.dh_send_private, session.dh_send_public = generate_x25519_keypair()
        session.dh_receive_public = x25519.X25519PublicKey.from_public_bytes(
            bytes.fromhex(recipient_info['spk_classic_public'])
        )

        # Вычисление общего секрета DH
        dh_shared_secret = x25519_derive_shared_secret(
            session.dh_send_private,
            serialize_x25519_public_key(session.dh_receive_public)
        )

        # Инициализация корневого и цепных ключей
        session.root_key, session.send_chain_key = self.kdf_rk(None, dh_shared_secret)
        session.receive_chain_key = session.send_chain_key  # Начальное значение

        self.user.sessions[recipient_username] = session

    async def prepare_message(self, recipient_username, plaintext):
        """
        Подготавливает зашифрованное сообщение для отправки.

        Args:
            recipient_username (str): Имя получателя.
            plaintext (bytes): Исходное сообщение.

        Returns:
            dict: Зашифрованное сообщение и метаданные.
        """
        session = self.user.sessions.get(recipient_username)
        if session is None:
            await self.initialize_session(recipient_username)
            session = self.user.sessions[recipient_username]

        # Проверка необходимости DH-рачета
        if session.send_message_index == 0:
            # Генерируем новую пару DH-ключей
            session.dh_send_private, session.dh_send_public = generate_x25519_keypair()

            # Выполняем DH-рачет
            dh_shared_secret = x25519_derive_shared_secret(
                session.dh_send_private,
                serialize_x25519_public_key(session.dh_receive_public)
            )

            # Обновляем корневой и цепной ключи
            session.root_key, session.send_chain_key = self.kdf_rk(session.root_key, dh_shared_secret)

        # Обновление цепного ключа отправителя
        session.send_chain_key = hmac_sha256(session.send_chain_key, b'ChainKey')

        # Генерация ключа сообщения
        message_key = hmac_sha256(session.send_chain_key, b'MessageKey')

        # Шифрование сообщения
        original_message_length = len(plaintext)
        padded_plaintext = pad_message(plaintext)
        ciphertext = encrypt(message_key, padded_plaintext)

        # Генерация MAC
        mac = hmac_sha256(message_key, ciphertext)

        # Подготовка заголовка
        header = {
            'dh': serialize_x25519_public_key(session.dh_send_public).hex(),
            'message_index': session.send_message_index,
            'original_length': original_message_length  # Добавлено для обфускации метаданных
        }

        session.send_message_index += 1

        return {
            'recipient': recipient_username,
            'payload': json.dumps({
                'header': header,
                'ciphertext': ciphertext.hex(),
                'mac': mac.hex()
            })
        }

    async def receive_message(self, sender_username, message):
        """
        Принимает и расшифровывает сообщение от отправителя.

        Args:
            sender_username (str): Имя отправителя.
            message (str): Полученное сообщение в формате JSON.

        Returns:
            bytes: Расшифрованное сообщение или None в случае ошибки.
        """
        session = self.user.sessions.get(sender_username)
        if session is None:
            await self.initialize_session(sender_username)
            session = self.user.sessions[sender_username]

        full_message = json.loads(message)
        header = full_message['header']
        ciphertext = bytes.fromhex(full_message['ciphertext'])
        mac = bytes.fromhex(full_message['mac'])

        dh_public_bytes = bytes.fromhex(header['dh'])
        dh_public_key = x25519.X25519PublicKey.from_public_bytes(dh_public_bytes)
        message_index = header['message_index']
        original_message_length = header.get('original_length')

        # Проверка на повторное сообщение
        if message_index in session.received_message_indices:
            logging.warning("Replay attack detected: message already received")
            return None

        session.received_message_indices.add(message_index)

        # Проверка необходимости DH-рачета
        if dh_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) != serialize_x25519_public_key(session.dh_receive_public):
            # Новый DH-рачет
            session.previous_receive_chain_keys[serialize_x25519_public_key(session.dh_receive_public)] = session.receive_chain_key

            # Обновляем DH-публичный ключ получателя
            session.dh_receive_public = dh_public_key

            # Выполняем DH-рачет
            dh_shared_secret = x25519_derive_shared_secret(
                self.user.ik_classic_private,
                serialize_x25519_public_key(session.dh_receive_public)
            )

            # Обновляем корневой и цепной ключи
            session.root_key, session.receive_chain_key = self.kdf_rk(session.root_key, dh_shared_secret)
            session.receive_message_index = 0

        # Обновление цепного ключа получателя
        session.receive_chain_key = hmac_sha256(session.receive_chain_key, b'ChainKey')

        # Генерация ключа сообщения
        message_key = hmac_sha256(session.receive_chain_key, b'MessageKey')

        # Проверка MAC и расшифровка
        try:
            if not verify_hmac(message_key, ciphertext, mac):
                raise Exception("Invalid MAC")

            padded_plaintext = decrypt(message_key, ciphertext)
            if padded_plaintext is None:
                raise Exception("Decryption failed")

            if original_message_length is not None:
                plaintext = unpad_message(padded_plaintext, original_message_length)
            else:
                plaintext = padded_plaintext.rstrip(b'\x00')

        except Exception as e:
            logging.error(f"Error receiving message from {sender_username}: {e}")
            return None

        session.receive_message_index += 1

        return plaintext

    def kdf_rk(self, root_key, dh_shared_secret):
        """
        Вычисляет новый корневой ключ и цепной ключ из корневого ключа и DH-общего секрета.

        Args:
            root_key (bytes): Текущий корневой ключ или None.
            dh_shared_secret (bytes): Общий секрет DH.

        Returns:
            tuple: (new_root_key, chain_key)
        """
        if root_key is None:
            root_key = b'\x00' * 32  # Начальное значение корневого ключа

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=root_key,
            info=b'Ratchet',
        )
        output = hkdf.derive(dh_shared_secret)
        new_root_key = output[:32]
        chain_key = output[32:]
        return new_root_key, chain_key
