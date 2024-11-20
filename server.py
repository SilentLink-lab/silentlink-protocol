# silentlink/server.py

import asyncio
import websockets
import json

class Server:
    def __init__(self):
        self.users = {}  # Список зарегистрированных пользователей и их публичных ключей
        self.connected_clients = {}  # Активные соединения

    async def handler(self, websocket, path):
        registration_message = await websocket.recv()
        reg_data = json.loads(registration_message)
        username = reg_data['username']
        self.connected_clients[username] = websocket

        # Сохранение публичных ключей пользователя
        self.users[username] = reg_data['public_keys']

        try:
            async for message in websocket:
                data = json.loads(message)
                recipient = data['recipient']
                payload = data['payload']

                if recipient in self.connected_clients:
                    recipient_ws = self.connected_clients[recipient]
                    await recipient_ws.send(json.dumps({
                        'sender': username,
                        'payload': payload
                    }))
                else:
                    # Получатель не в сети
                    pass
        finally:
            del self.connected_clients[username]

    def start(self):
        start_server = websockets.serve(self.handler, 'localhost', 8765)
        asyncio.get_event_loop().run_until_complete(start_server)
        print("Server started on ws://localhost:8765")
        asyncio.get_event_loop().run_forever()
