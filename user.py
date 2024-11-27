# user.py

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
import logging

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
        self.ik_classic_private, self.ik_classic_public = \
            generate_x25519_keypair()
        self.spk_classic_private, self.spk_classic_public = \
            generate_x25519_keypair()

        # Постквантовые ключи
        self.ik_pq_private, self.ik_pq_public = generate_kyber_keypair()
        self.spk_pq_private, self.spk_pq_public = generate_kyber_keypair()

        # Подпись SPK с использованием Dilithium
        self.dilithium_private_key, self.dilithium_public_key = \
            generate_dilithium_keypair()
        self.spk_signature = dilithium_sign_message(
            self.dilithium_private_key,
            serialize_x25519_public_key(
                self.spk_classic_public) + self.spk_pq_public
        )

        self.sessions = {}
        self.websocket = None
        self.server_uri = None
        self.keep_running = True  # Для контроля цикла
        self.message_queue = asyncio.Queue()

    async def connect(self, server_uri):
        """
        Подключается к серверу и регистрирует пользователя.

        Args:
            server_uri (str): URI сервера WebSocket.
        """
        self.server_uri = server_uri

        while self.keep_running:
            try:
                async with websockets.connect(server_uri) as websocket:
                    self.websocket = websocket

                    # Регистрация пользователя
                    await self.register()

                    # Запуск задач прослушивания и отправки сообщений
                    listener_task = asyncio.create_task(self.listen())
                    sender_task = asyncio.create_task(self.send_messages())

                    await asyncio.gather(listener_task, sender_task)
            except (websockets.ConnectionClosedError,
                    ConnectionRefusedError):
                logging.warning("Connection lost. Reconnecting...")
                await asyncio.sleep(5)
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                await asyncio.sleep(5)

    async def register(self):
        """
        Регистрирует пользователя на сервере.
        """
        registration_data = {
            'action': 'register',
            'username': self.username,
            'public_keys': {
                'ik_classic_public': serialize_x25519_public_key(
                    self.ik_classic_public).hex(),
                'spk_classic_public': serialize_x25519_public_key(
                    self.spk_classic_public).hex(),
                'ik_pq_public': self.ik_pq_public.hex(),
                'spk_pq_public': self.spk_pq_public.hex(),
                'spk_signature': self.spk_signature.hex()
            }
        }

        await self.websocket.send(json.dumps(registration_data))
        response = await self.websocket.recv()
        data = json.loads(response)
        if data.get('status') != 'success':
            raise Exception("Registration failed")

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
                print(f"Received from {sender}: {plaintext.decode()}")
        except websockets.ConnectionClosedError:
            logging.warning("Connection closed by server.")

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

    async def get_recipient_info(self, recipient_username):
        """
        Получает информацию о получателе от сервера.

        Args:
            recipient_username (str): Имя получателя.

        Returns:
            dict: Информация о публичных ключах получателя.
        """
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
        Добавляет сообщение в очередь для отправки.

        Args:
            recipient_username (str): Имя получателя.
            plaintext (bytes): Сообщение для отправки.
        """
        protocol = Protocol(self)
        encrypted_message = await protocol.prepare_message(
            recipient_username, plaintext)
        await self.message_queue.put(encrypted_message)
