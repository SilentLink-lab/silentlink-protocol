# server.py

import json
import logging
import asyncio
from typing import Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

import aioredis

logging.basicConfig(level=logging.INFO)

app = FastAPI()

# Настройка CORS (при необходимости)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключение к Redis
redis = None

@app.on_event("startup")
async def startup_event():
    global redis
    redis = await aioredis.create_redis_pool('redis://localhost')
    logging.info("Connected to Redis")

@app.on_event("shutdown")
async def shutdown_event():
    redis.close()
    await redis.wait_closed()
    logging.info("Disconnected from Redis")

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        self.user_devices: Dict[str, Dict[str, dict]] = {}
        self.user_certificates: Dict[str, dict] = {}

    async def connect(self, username: str, device_id: str, websocket: WebSocket):
        await websocket.accept()
        if username not in self.active_connections:
            self.active_connections[username] = {}
        self.active_connections[username][device_id] = websocket
        logging.info(f"User {username} connected with device {device_id}")

    def disconnect(self, username: str, device_id: str):
        if username in self.active_connections:
            if device_id in self.active_connections[username]:
                del self.active_connections[username][device_id]
                logging.info(f"User {username} disconnected device {device_id}")
            if not self.active_connections[username]:
                del self.active_connections[username]

    async def send_personal_message(self, message: str, username: str):
        if username in self.active_connections:
            for ws in self.active_connections[username].values():
                await ws.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/{username}/{device_id}")
async def websocket_endpoint(websocket: WebSocket, username: str, device_id: str):
    await manager.connect(username, device_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await process_message(websocket, username, device_id, data)
    except WebSocketDisconnect:
        manager.disconnect(username, device_id)

async def process_message(websocket: WebSocket, username: str, device_id: str, message: str):
    data = json.loads(message)
    action = data.get('action')

    if action == 'register':
        await handle_register(websocket, username, device_id, data)
    elif action == 'get_user_info':
        await handle_get_user_info(websocket, data)
    elif action == 'send_messages':
        await handle_send_messages(websocket, username, data)
    elif action == 'list_devices':
        await handle_list_devices(websocket, username)
    elif action == 'remove_device':
        await handle_remove_device(websocket, username, data)
    else:
        await websocket.send_text(json.dumps({
            'status': 'error',
            'message': 'Invalid action'
        }))

async def handle_register(websocket: WebSocket, username: str, device_id: str, data: dict):
    certificate = data['certificate']

    # Сохраняем сертификат и устройство пользователя в Redis
    await redis.hset(f"user:{username}:devices", device_id, json.dumps({
        'certificate': certificate
    }))
    await redis.hset("user_certificates", username, json.dumps(certificate))

    # Обновляем информацию в менеджере соединений
    manager.user_devices.setdefault(username, {})[device_id] = {
        'certificate': certificate
    }
    manager.user_certificates[username] = certificate

    await websocket.send_text(json.dumps({'status': 'success'}))
    logging.info(f"User {username} registered with device {device_id}")

async def handle_get_user_info(websocket: WebSocket, data: dict):
    target_username = data['username']
    certificate = await redis.hget("user_certificates", target_username)
    if certificate:
        await websocket.send_text(json.dumps({
            'status': 'success',
            'certificate': json.loads(certificate)
        }))
    else:
        await websocket.send_text(json.dumps({
            'status': 'error',
            'message': 'User not found'
        }))

async def handle_send_messages(websocket: WebSocket, sender_username: str, data: dict):
    messages = data.get('messages', [])
    for msg in messages:
        recipient = msg['recipient']
        if recipient == 'dummy_recipient':
            # Обрабатываем фиктивные сообщения особым образом или игнорируем
            continue

        # Публикуем сообщение в Redis для получателя
        await redis.publish_json(f"user:{recipient}:messages", {
            'sender': sender_username,
            'payload': msg['payload']
        })
    await websocket.send_text(json.dumps({'status': 'success'}))

async def handle_list_devices(websocket: WebSocket, username: str):
    devices = await redis.hkeys(f"user:{username}:devices")
    devices = [device.decode('utf-8') for device in devices]
    if devices:
        await websocket.send_text(json.dumps({
            'status': 'success',
            'devices': devices
        }))
    else:
        await websocket.send_text(json.dumps({
            'status': 'error',
            'message': 'No devices found'
        }))

async def handle_remove_device(websocket: WebSocket, username: str, data: dict):
    device_id = data['device_id']
    result = await redis.hdel(f"user:{username}:devices", device_id)
    if result:
        # Обновляем информацию в менеджере соединений
        manager.user_devices[username].pop(device_id, None)
        manager.active_connections[username].pop(device_id, None)
        await websocket.send_text(json.dumps({'status': 'success'}))
        logging.info(f"Device {device_id} removed for user {username}")
    else:
        await websocket.send_text(json.dumps({
            'status': 'error',
            'message': 'Device not found'
        }))

# Фоновая задача для доставки сообщений
@app.on_event("startup")
async def start_message_delivery():
    asyncio.create_task(message_delivery_loop())

async def message_delivery_loop():
    pubsub = await redis.psubscribe('user:*:messages')
    ch = pubsub[0]
    while True:
        try:
            message = await ch.get(encoding='utf-8')
            if message is not None:
                data = json.loads(message)
                channel = ch.pattern.decode('utf-8')
                recipient_username = channel.split(":")[1]
                await manager.send_personal_message(
                    json.dumps(data),
                    recipient_username
                )
        except Exception as e:
            logging.error(f"Error in message delivery: {e}")
            await asyncio.sleep(1)
