# examples/example.py

import asyncio
from silentlink.user import User
from silentlink.protocol import Protocol

async def main():
    # Создаем пользователей Alice и Bob
    alice = User('Alice')
    bob = User('Bob')

    # Подключаемся к серверу
    await alice.connect('ws://localhost:8765')
    await bob.connect('ws://localhost:8765')

    # Создаем протоколы для Alice и Bob
    alice_protocol = Protocol(alice)
    bob_protocol = Protocol(bob)

    # Запускаем задачи для прослушивания входящих сообщений
    asyncio.create_task(alice.listen())
    asyncio.create_task(bob.listen())

    # Alice отправляет сообщение Bob
    plaintext = b'Привет, Bob! Это Alice.'
    await alice_protocol.send_message('Bob', plaintext)

    # Bob отправляет ответ Alice
    reply = b'Привет, Alice! Это Bob.'
    await bob_protocol.send_message('Alice', reply)

    # Ожидаем некоторое время для обмена сообщениями
    await asyncio.sleep(10)

if __name__ == '__main__':
    asyncio.run(main())
