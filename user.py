# silentlink/user.py

from .crypto import (
    generate_x25519_keypair,
    generate_kyber_keypair,
    generate_dilithium_keypair,
    serialize_x25519_public_key,
    serialize_kyber_public_key,
    dilithium_sign_message
)
import uuid
import json
import asyncio
import websockets

class User:
    def __init__(self, username):
        """
        Инициализирует пользователя.

        Args:
            username (str): Имя пользователя.
        """
        self.username = username
        self.device_id = str(uuid.uuid4())

        # Классические ключи
        self.ik_classic_private, self.ik_classic_public = generate_x25519_keypair()
        self.spk_classic_private, self.spk_classic_public = generate_x25519_keypair()

        # Постквантовые ключи
        self.ik_pq_private, self.ik_pq_public = generate_kyber_keypair()
        self.spk_pq_private, self.spk_pq_public = generate_kyber_keypair()

        # Подпись SPK с использованием Dilithium
        self.dilithium_private_key, self.dilithium_public_key = generate_dilithium_keypair()
        self.spk_signature = dilithium_sign_message(
            self.dilithium_private_key,
            serialize_x25519_public_key(self.spk_classic_public) + self.spk_pq_public
        )

        self.sessions = {}
        self.websocket = None
        self.server_uri = None

    async def connect(self, server_uri):
        """
        Подключается к серверу и регистрирует пользователя.

        Args:
            server_uri (str): URI сервера WebSocket.
        """
        self.server_uri = server_uri
        self.websocket = await websockets.connect(server_uri)

        # Подготовка данных для регистрации
        registration_data = {
            'username': self.username,
            'public_keys': {
                'ik_classic_public': serialize_x25519_public_key(self.ik_classic_public).hex(),
                'spk_classic_public': serialize_x25519_public_key(self.spk_classic_public).hex(),
                'ik_pq_public': self.ik_pq_public.hex(),
                'spk_pq_public': self.spk_pq_public.hex(),
                'spk_signature': self.spk_signature.hex()
                # Добавьте другие необходимые данные
            }
        }

        await self.websocket.send(json.dumps(registration_data))

    async def listen(self):
        """
        Прослушивает входящие сообщения от сервера.
        """
        async for message in self.websocket:
            data = json.loads(message)
            sender = data['sender']
            payload = data['payload']
            protocol = Protocol(self)
            plaintext = await protocol.receive_message(sender, payload)
            print(f"Received message from {sender}: {plaintext.decode()}")

    async def get_recipient_info(self, recipient_username):
        """
        Получает информацию о получателе от сервера.

        Args:
            recipient_username (str): Имя пользователя получателя.

        Returns:
            dict: Информация о публичных ключах получателя.
        """
        # Запрос информации о получателе у сервера
        # В данном примере предполагается, что сервер хранит публичные ключи пользователей
        await self.websocket.send(json.dumps({
            'action': 'get_user_info',
            'username': recipient_username
        }))
        response = await self.websocket.recv()
        data = json.loads(response)
        if data['status'] == 'success':
            return data['public_keys']
        else:
            return None

    async def send_message(self, recipient_username, plaintext):
        """
        Отправляет сообщение получателю.

        Args:
            recipient_username (str): Имя пользователя получателя.
            plaintext (bytes): Сообщение для отправки.
        """
        protocol = Protocol(self)
        await protocol.send_message(recipient_username, plaintext)
