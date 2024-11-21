# silentlink/protocol.py

from .crypto import *
from .utils import concat, pad_message, unpad_message
import json

class Session:
    def __init__(self):
        """
        Инициализирует сессию для обмена сообщениями между двумя пользователями.
        """
        # Корневой ключ и цепные ключи для Double Ratchet
        self.root_key = None
        self.send_chain_key = None
        self.receive_chain_key = None

        # Диффи-Хеллман ключи
        self.dh_send_private = None
        self.dh_send_public = None
        self.dh_receive_public = None

        # Индексы сообщений
        self.send_message_index = 0
        self.receive_message_index = 0

class Protocol:
    def __init__(self, user):
        """
        Инициализирует протокол для пользователя.

        Args:
            user (User): Объект пользователя.
        """
        self.user = user

    async def initialize_session(self, recipient_username):
        """
        Инициализирует сессию с получателем.

        Args:
            recipient_username (str): Имя пользователя получателя.
        """
        # Получение информации о получателе
        recipient_info = await self.user.get_recipient_info(recipient_username)
        if recipient_info is None:
            raise Exception("Recipient information not available")

        session = Session()

        # Генерация эфемерных ключей
        ek_classic_private, ek_classic_public = generate_x25519_keypair()
        ek_pq_private, ek_pq_public = generate_kyber_keypair()

        # Сериализация публичных ключей
        ek_classic_public_bytes = serialize_x25519_public_key(ek_classic_public)

        # Вычисление классических общих секретов
        dh1_classic = x25519_derive_shared_secret(
            ek_classic_private,
            bytes.fromhex(recipient_info['ik_classic_public'])
        )
        dh2_classic = x25519_derive_shared_secret(
            ek_classic_private,
            bytes.fromhex(recipient_info['spk_classic_public'])
        )
        dh3_classic = x25519_derive_shared_secret(
            ek_classic_private,
            bytes.fromhex(recipient_info['opk_classic_public'])
        )
        dh4_classic = x25519_derive_shared_secret(
            self.user.ik_classic_private,
            bytes.fromhex(recipient_info['spk_classic_public'])
        )

        # Вычисление постквантовых общих секретов
        # Предполагается, что recipient_info содержит необходимые данные для Kyber
        dh1_pq = kyber_decrypt_message(ek_pq_private, bytes.fromhex(recipient_info['ik_pq_public']))
        dh2_pq = kyber_decrypt_message(ek_pq_private, bytes.fromhex(recipient_info['spk_pq_public']))
        dh3_pq = kyber_decrypt_message(ek_pq_private, bytes.fromhex(recipient_info['opk_pq_public']))
        dh4_pq = kyber_decrypt_message(self.user.ik_pq_private, bytes.fromhex(recipient_info['spk_pq_public']))

        # Комбинирование общих секретов
        master_secret = hkdf_extract_and_expand(
            salt=None,
            input_key_material=concat(
                dh1_classic, dh2_classic, dh3_classic, dh4_classic,
                dh1_pq, dh2_pq, dh3_pq, dh4_pq
            ),
            info=b'SilentLink Master Secret'
        )

        # Инициализация цепных ключей
        session.root_key = master_secret
        session.send_chain_key = session.root_key
        session.receive_chain_key = session.root_key

        # Сохранение сессии
        self.user.sessions[recipient_username] = session

    async def send_message(self, recipient_username, plaintext):
        """
        Отправляет зашифрованное сообщение получателю.

        Args:
            recipient_username (str): Имя пользователя получателя.
            plaintext (bytes): Сообщение для отправки.
        """
        session = self.user.sessions.get(recipient_username)
        if session is None:
            await self.initialize_session(recipient_username)
            session = self.user.sessions[recipient_username]

        # Паддинг сообщения
        padded_plaintext = pad_message(plaintext)

        # Обновление цепного ключа отправителя
        session.send_chain_key = hmac_sha256(session.send_chain_key, b'ChainKey')

        # Генерация ключа сообщения
        message_key = hmac_sha256(session.send_chain_key, b'MessageKey')

        # Шифрование сообщения
        ciphertext = encrypt(message_key, padded_plaintext)

        # Генерация MAC
        mac = generate_hmac(message_key, ciphertext)

        # Подготовка заголовка
        header = {
            'dh': serialize_x25519_public_key(session.dh_send_public).hex(),
            'ratchet_index': session.send_message_index
        }

        # Отправка сообщения
        await self.user.websocket.send(json.dumps({
            'recipient': recipient_username,
            'payload': json.dumps({
                'header': header,
                'ciphertext': ciphertext.hex(),
                'mac': mac.hex()
            })
        }))

        session.send_message_index += 1

    async def receive_message(self, sender_username, message):
        """
        Принимает и расшифровывает сообщение от отправителя.

        Args:
            sender_username (str): Имя пользователя отправителя.
            message (str): Полученное сообщение в формате JSON.

        Returns:
            bytes: Расшифрованное сообщение.
        """
        session = self.user.sessions.get(sender_username)
        if session is None:
            await self.initialize_session(sender_username)
            session = self.user.sessions[sender_username]

        # Извлечение компонентов сообщения
        full_message = json.loads(message)
        header = full_message['header']
        ciphertext = bytes.fromhex(full_message['ciphertext'])
        mac = bytes.fromhex(full_message['mac'])

        # Обновление цепного ключа получателя
        session.receive_chain_key = hmac_sha256(session.receive_chain_key, b'ChainKey')

        # Генерация ключа сообщения
        message_key = hmac_sha256(session.receive_chain_key, b'MessageKey')

        # Проверка MAC
        if not verify_hmac(message_key, ciphertext, mac):
            raise Exception("MAC verification failed")

        # Расшифровка сообщения
        padded_plaintext = decrypt(message_key, ciphertext)
        if padded_plaintext is None:
            raise Exception("Decryption failed")

        # Удаление паддинга
        plaintext = unpad_message(padded_plaintext)

        session.receive_message_index += 1

        return plaintext
