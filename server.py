# server.py

import asyncio
import json
import websockets

class Server:
    def __init__(self):
        """
        Инициализирует сервер SilentLink.
        """
        self.connected_clients = {}  # {username: websocket}
        self.user_certificates = {}  # {username: certificate}
        self.user_devices = {}       # {username: {device_id: device_info}}

    async def handler(self, websocket, path):
        """
        Обрабатывает входящие соединения и сообщения.

        Args:
            websocket (WebSocketServerProtocol): Веб-сокет соединение.
            path (str): Путь запроса.
        """
        try:
            async for message in websocket:
                data = json.loads(message)
                action = data.get('action')

                if action == 'register':
                    username = data['username']
                    device_id = data['device_id']
                    certificate = data['certificate']

                    if username not in self.user_devices:
                        self.user_devices[username] = {}

                    self.user_devices[username][device_id] = {
                        'certificate': certificate,
                        'websocket': websocket
                    }
                    self.user_certificates[username] = certificate  # Можно хранить по устройствам

                    await websocket.send(json.dumps({'status': 'success'}))

                elif action == 'get_user_info':
                    target_username = data['username']
                    if target_username in self.user_certificates:
                        await websocket.send(json.dumps({
                            'status': 'success',
                            'certificate': self.user_certificates[target_username]
                        }))
                    else:
                        await websocket.send(json.dumps({
                            'status': 'error',
                            'message': 'User not found'
                        }))

                elif action == 'send_messages':
                    messages = data.get('messages', [])
                    for msg in messages:
                        recipient = msg['recipient']
                        if recipient == 'dummy_recipient':
                            # Игнорируем фиктивные сообщения или обрабатываем их особым образом
                            continue
                        if recipient in self.user_devices:
                            for device in self.user_devices[recipient].values():
                                recipient_websocket = device['websocket']
                                await recipient_websocket.send(json.dumps({
                                    'sender': data.get('username'),
                                    'payload': msg['payload']
                                }))
                    await websocket.send(json.dumps({'status': 'success'}))

                elif action == 'list_devices':
                    username = data['username']
                    if username in self.user_devices:
                        devices = list(self.user_devices[username].keys())
                        await websocket.send(json.dumps({
                            'status': 'success',
                            'devices': devices
                        }))
                    else:
                        await websocket.send(json.dumps({
                            'status': 'error',
                            'message': 'No devices found'
                        }))

                elif action == 'remove_device':
                    username = data['username']
                    device_id = data['device_id']
                    if username in self.user_devices and device_id in self.user_devices[username]:
                        del self.user_devices[username][device_id]
                        await websocket.send(json.dumps({'status': 'success'}))
                    else:
                        await websocket.send(json.dumps({
                            'status': 'error',
                            'message': 'Device not found'
                        }))

                else:
                    await websocket.send(json.dumps({
                        'status': 'error',
                        'message': 'Invalid action'
                    }))

        except websockets.ConnectionClosed:
            pass  # Обработка разрыва соединения

    def start(self):
        """
        Запускает сервер WebSocket.
        """
        start_server = websockets.serve(self.handler, 'localhost', 8765)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

if __name__ == '__main__':
    server = Server()
    server.start()
