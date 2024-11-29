# user.py

import asyncio
import json
import uuid
import os
import logging
import websockets
import random

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import (
    generate_kyber_keypair,
    hkdf_extract_and_expand
)
from .protocol import Protocol

logging.basicConfig(level=logging.INFO)

class User:
    def __init__(self, username, password):
        """
        Инициализирует пользователя.

        Args:
            username (str): Имя пользователя.
            password (str): Пароль для шифрования приватных ключей.
        """
        self.username = username
        self.password = password
        self.device_id = str(uuid.uuid4())

        # Генерация ключа для шифрования приватных ключей
        self.encryption_key = self.derive_key_from_password(password)

        # Генерация долговременных ключей подписи (Ed25519)
        self.identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()
        self.identity_public_key_bytes = self.identity_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Kyber ключи
        self.kyber_private_key, self.kyber_public_key = generate_kyber_keypair()

        # Сессии с другими пользователями
        self.sessions = {}

        # Хранение публичных ключей идентификации получателей
        self.recipient_identity_public_keys = {}

        self.websocket = None
        self.server_uri = None
        self.keep_running = True  # Флаг для контроля цикла
        self.message_queue = asyncio.Queue()

    def derive_key_from_password(self, password):
        """
        Генерирует ключ для шифрования приватных ключей из пароля пользователя.

        Args:
            password (str): Пароль пользователя.

        Returns:
            bytes: Ключ для шифрования.
        """
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(password.encode())
        return key

    def encrypt_private_key(self, private_key_bytes):
        """
        Шифрует приватный ключ.

        Args:
            private_key_bytes (bytes): Байтовое представление приватного ключа.

        Returns:
            bytes: Зашифрованный приватный ключ.
        """
        # Реализация шифрования (например, с использованием AES-GCM)
        # Необходимо добавить соответствующий код
        pass

    def decrypt_private_key(self, encrypted_private_key_bytes):
        """
        Расшифровывает приватный ключ.

        Args:
            encrypted_private_key_bytes (bytes): Зашифрованный приватный ключ.

        Returns:
            bytes: Расшифрованный приватный ключ.
        """
        # Реализация расшифровки
        # Необходимо добавить соответствующий код
        pass

    def generate_key_certificate(self):
        """
        Генерирует сертификат публичных ключей с подписью.

        Returns:
            dict: Сертификат публичных ключей.
        """
        public_keys_data = {
            'username': self.username,
            'device_id': self.device_id,
            'kyber_public_key': self.kyber_public_key.hex(),
            'identity_public_key': self.identity_public_key_bytes.hex()
            # Добавьте другие публичные ключи, если необходимо
        }
        public_keys_json = json.dumps(public_keys_data).encode()
        signature = self.identity_private_key.sign(public_keys_json)
        certificate = {
            'public_keys': public_keys_data,
            'signature': signature.hex()
        }
        return certificate

    async def connect(self, server_uri):
        """
        Подключается к серверу и регистрирует пользователя.

        Args:
            server_uri (str): URI сервера WebSocket.
        """
        self.server_uri = server_uri

        while self.keep_running:
            try:
                websocket_uri = f"{server_uri}/ws/{self.username}/{self.device_id}"
                async with websockets.connect(websocket_uri) as websocket:
                    self.websocket = websocket

                    # Регистрация пользователя
                    await self.register()

                    # Запуск задач прослушивания и отправки сообщений
                    listener_task = asyncio.create_task(self.listen())
                    sender_task = asyncio.create_task(self.send_messages())
                    dummy_task = asyncio.create_task(self.send_dummy_messages())

                    await asyncio.gather(listener_task, sender_task, dummy_task)
            except (websockets.ConnectionClosedError, ConnectionRefusedError):
                logging.warning("Connection lost. Reconnecting...")
                await asyncio.sleep(5)
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                await asyncio.sleep(5)

    async def register(self):
        """
        Регистрирует пользователя на сервере.
        """
        key_certificate = self.generate_key_certificate()
        registration_data = {
            'action': 'register',
            'username': self.username,
            'device_id': self.device_id,
            'certificate': key_certificate
        }

        await self.websocket.send(json.dumps(registration_data))
        response = await self.websocket.recv()
        data = json.loads(response)
        if data.get('status') != 'success':
            raise Exception("Registration failed")
        logging.info(f"User {self.username} registered successfully.")

    async def listen(self):
        """
        Прослушивает входящие сообщения от сервера.
        """
        try:
            async for message in self.websocket:
                data = json.loads(message)
                sender = data['sender']
                payload = data['payload']
                protocol = Protocol(self)
                plaintext = await protocol.receive_message(sender, payload)
                if plaintext:
                    print(f"Received from {sender}: {plaintext.decode()}")
        except websockets.ConnectionClosedError:
            logging.warning("Connection closed by server.")
        except Exception as e:
            logging.error(f"Error in listen: {e}")

    async def send_messages(self):
        """
        Отправляет сообщения из очереди на сервер пакетами.
        """
        while self.keep_running:
            messages_to_send = []
            try:
                # Собираем сообщения в пакет
                while not self.message_queue.empty():
                    message = await self.message_queue.get()
                    messages_to_send.append(message)

                if messages_to_send:
                    await self.websocket.send(json.dumps({
                        'action': 'send_messages',
                        'messages': messages_to_send
                    }))

                # Ждем перед следующей отправкой
                await asyncio.sleep(0.1)
            except Exception as e:
                logging.error(f"Error sending messages: {e}")
                await asyncio.sleep(1)

    async def send_dummy_messages(self):
        """
        Периодически отправляет фиктивные сообщения для обфускации трафика.
        """
        while self.keep_running:
            try:
                # Ждем случайное время перед отправкой фиктивного сообщения
                await asyncio.sleep(random.uniform(5, 15))  # Интервал можно настроить

                # Выбираем специального фиктивного получателя
                dummy_recipient = 'dummy_recipient'

                # Создаем фиктивное сообщение
                dummy_message = os.urandom(256)  # Случайные данные

                # Отправляем сообщение
                protocol = Protocol(self)
                encrypted_message = await protocol.prepare_message(dummy_recipient, dummy_message)
                await self.message_queue.put(encrypted_message)
            except Exception as e:
                logging.error(f"Error sending dummy message: {e}")

    async def get_recipient_info(self, recipient_username):
        """
        Получает и проверяет информацию о получателе.

        Args:
            recipient_username (str): Имя пользователя получателя.

        Returns:
            dict: Проверенные публичные ключи получателя.
        """
        await self.websocket.send(json.dumps({
            'action': 'get_user_info',
            'username': recipient_username
        }))
        response = await self.websocket.recv()
        data = json.loads(response)
        if data['status'] == 'success':
            certificate = data['certificate']
            public_keys_data = certificate['public_keys']
            signature = bytes.fromhex(certificate['signature'])

            # Восстанавливаем публичный ключ идентификации получателя
            recipient_identity_public_key_bytes = bytes.fromhex(public_keys_data['identity_public_key'])
            recipient_identity_public_key = ed25519.Ed25519PublicKey.from_public_bytes(recipient_identity_public_key_bytes)

            # Проверяем подпись сертификата
            public_keys_json = json.dumps(public_keys_data).encode()
            try:
                recipient_identity_public_key.verify(signature, public_keys_json)
            except ed25519.InvalidSignature:
                raise Exception("Invalid signature on recipient's certificate")

            # Проверяем, не изменился ли публичный ключ идентификации
            stored_public_key = self.recipient_identity_public_keys.get(recipient_username)
            if stored_public_key and stored_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ) != recipient_identity_public_key_bytes:
                # Ключ изменился, уведомляем пользователя
                print(f"Warning: Identity key for {recipient_username} has changed!")
                # Можно запросить подтверждение у пользователя

            # Сохраняем публичный ключ идентификации получателя
            self.recipient_identity_public_keys[recipient_username] = recipient_identity_public_key

            return public_keys_data
        else:
            logging.error(f"Failed to get recipient info for {recipient_username}")
            return None

    async def send_message(self, recipient_username, plaintext):
        """
        Добавляет сообщение в очередь для отправки.

        Args:
            recipient_username (str): Имя получателя.
            plaintext (bytes): Сообщение для отправки.
        """
        protocol = Protocol(self)
        encrypted_message = await protocol.prepare_message(recipient_username, plaintext)
        await self.message_queue.put(encrypted_message)

    async def list_devices(self):
        """
        Получает список устройств пользователя с сервера.

        Returns:
            list: Список устройств.
        """
        await self.websocket.send(json.dumps({
            'action': 'list_devices',
            'username': self.username
        }))
        response = await self.websocket.recv()
        data = json.loads(response)
        if data['status'] == 'success':
            devices = data['devices']
            return devices
        else:
            logging.error(f"Failed to list devices for {self.username}")
            return None

    async def remove_device(self, device_id):
        """
        Удаляет устройство пользователя.

        Args:
            device_id (str): Идентификатор устройства.

        Returns:
            bool: True, если успешно, иначе False.
        """
        await self.websocket.send(json.dumps({
            'action': 'remove_device',
            'username': self.username,
            'device_id': device_id
        }))
        response = await self.websocket.recv()
        data = json.loads(response)
        if data['status'] == 'success':
            logging.info(f"Device {device_id} removed successfully.")
            return True
        else:
            logging.error(f"Failed to remove device {device_id}")
            return False
