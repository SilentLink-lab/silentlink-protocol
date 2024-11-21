# examples/client_bob.py

import asyncio
from silentlink.user import User
from silentlink.protocol import Protocol

async def main():
    # Создаем пользователя Bob и подключаемся к серверу
    bob = User('Bob')
    await bob.connect('ws://localhost:8765')

    # Создаем протокол для Bob
    bob_protocol = Protocol(bob)

    # Запускаем задачу для прослушивания входящих сообщений
    asyncio.create_task(bob.listen())

    # Ожидаем немного времени для установления соединения
    await asyncio.sleep(1)

    # Ожидаем получения сообщений и отвечаем Alice
    await asyncio.sleep(5)

    # Отправляем ответ Alice
    reply = b'Привет, Alice! Это Bob.'
    await bob_protocol.send_message('Alice', reply)

    # Ожидаем некоторое время для обмена сообщениями
    await asyncio.sleep(10)

if __name__ == '__main__':
    asyncio.run(main())
