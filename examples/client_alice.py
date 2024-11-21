# examples/client_alice.py

import asyncio
from silentlink.user import User
from silentlink.protocol import Protocol

async def main():
    # Создаем пользователя Alice и подключаемся к серверу
    alice = User('Alice')
    await alice.connect('ws://localhost:8765')

    # Создаем протокол для Alice
    alice_protocol = Protocol(alice)

    # Запускаем задачу для прослушивания входящих сообщений
    asyncio.create_task(alice.listen())

    # Ожидаем немного времени для установления соединения
    await asyncio.sleep(1)

    # Отправляем сообщение Bob
    plaintext = b'Привет, Bob! Это Alice.'
    await alice_protocol.send_message('Bob', plaintext)

    # Ожидаем получения сообщений
    await asyncio.sleep(10)

if __name__ == '__main__':
    asyncio.run(main())
