# silentlink/user.py

from .crypto import generate_x25519_keypair, generate_kyber_keypair, generate_dilithium_keypair, serialize_public_key, dilithium_sign_message
import uuid
import json
import asyncio
import websockets

class User:
    def __init__(self, username):
        self.username = username
        self.device_id = str(uuid.uuid4())

        # Классические ключи
        self.ik_classic_private, self.ik_classic_public = generate_x25519_keypair()
        self.spk_classic_private, self.spk_classic_public = generate_x25519_keypair()

        # Постквантовые ключи
        self.ik_pq_private, self.ik_pq_public = generate_kyber_keypair()
        self.spk_pq_private, self.spk_pq_public = generate_kyber_keypair()

        # Подпись SPK
        # Здесь добавьте код для подписания SPK с помощью Dilithium
        # self.spk_pq_signature = dilithium_sign_message(self.ik_pq_private, self.spk_pq_public)

        self.sessions = {}
        self.websocket = None
        self.server_uri = None

    async def connect(self, server_uri):
        self.server_uri = server_uri
        self.websocket = await websockets.connect(server_uri)

        # Подготовка данных для регистрации
        registration_data = {
            'username': self.username,
            'public_keys': {
                'ik_classic_public': serialize_public_key(self.ik_classic_public).hex(),
                'spk_classic_public': serialize_public_key(self.spk_classic_public).hex(),
                'ik_pq_public': self.ik_pq_public.hex(),
                'spk_pq_public': self.spk_pq_public.hex(),
                # Добавьте подписи и другие необходимые данные
            }
        }

        await self.websocket.send(json.dumps(registration_data))

    async def listen(self):
        async for message in self.websocket:
            data = json.loads(message)
            sender = data['sender']
            payload = data['payload']
            protocol = Protocol(self)
            plaintext = await protocol.receive_message(sender, payload)
            print(f"Received message from {sender}: {plaintext.decode()}")

    async def get_recipient_info(self, recipient_username):
        # Запрос информации о получателе у сервера
        # В данном примере предполагается, что сервер хранит публичные ключи пользователей
        async with websockets.connect(self.server_uri) as ws:
            await ws.send(json.dumps({'action': 'get_user_info', 'username': recipient_username}))
            response = await ws.recv()
            data = json.loads(response)
            if data['status'] == 'success':
                return data['public_keys']
            else:
                return None

    async def send_message(self, recipient_username, plaintext):
        protocol = Protocol(self)
        await protocol.send_message(recipient_username, plaintext)
