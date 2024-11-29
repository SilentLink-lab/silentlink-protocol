# Donate
**Bitcoin** - 1GYpJpKSi1Sn7LXexYfva8Yvu5u7WkwJbo

**ETH ERC20** -0x7b6da964518b161ea8b2f1d83f12f99615380984

**USDT TRC20** - TLLx5Pie2BDkRbDRxTxBa28YTaMgg7uuzr

**Dogecoin** - DEs46phF9Sa1ReNSD853TzLcg9JkxfWeQL

# SilentLink — Протокол безопасного обмена сообщениями

## Описание

**SilentLink** — это современный протокол сквозного шифрования, разработанный для обеспечения безопасного и приватного обмена сообщениями в режиме реального времени. Он ориентирован на максимальную защиту данных пользователей, используя передовые криптографические методы, включая постквантовые алгоритмы, и предоставляет функциональность для безопасных групповых чатов и поддержки нескольких устройств.

## Особенности

- **Сквозное шифрование:** Обеспечивает конфиденциальность сообщений от отправителя до получателя.
- **Совершенная прямая секретность (PFS):** Компрометация текущих ключей не раскрывает прошлые сообщения.
- **Постквантовая безопасность:** Использует алгоритмы, устойчивые к квантовым атакам (при использовании соответствующих библиотек).
- **Поддержка нескольких устройств:** Пользователь может использовать несколько устройств одновременно с безопасной синхронизацией.
- **Групповые чаты:** Безопасный групповой обмен сообщениями.
- **Сокрытие метаданных:** Методы для скрытия размера сообщений, времени отправки и получателя.
- **Правдоподобное отрицание:** Отправитель может отрицать факт отправки конкретного сообщения.
- **Открытый исходный код:** Проект открыт для сообщества и доступен для аудита.

## Обновления и улучшения

### Усиление механизмов аутентификации и проверки подлинности ключей

- **Цифровые подписи:** Внедрены цифровые подписи с использованием алгоритма Ed25519 для аутентификации публичных ключей пользователей.
- **Механизм TOFU:** Реализован механизм Trust On First Use (TOFU) с уведомлениями о смене ключей, позволяющий пользователям отслеживать изменения в публичных ключах собеседников.

### Полная реализация протокола Double Ratchet

- **DH-рачеты и симметричные рачеты:** Полностью реализован протокол Double Ratchet, включая Диффи-Хеллмана рачеты и симметричные рачеты для обновления ключей.
- **PFS и защита после компрометации:** Обеспечена совершенная прямая секретность и защита после компрометации ключей.

### Защита от повторных отправок сообщений (Replay Attack)

- **Отслеживание индексов сообщений:** Внедрен механизм отслеживания индексов полученных сообщений для предотвращения обработки дубликатов.
- **Улучшенная обработка ошибок:** Добавлено подробное логирование и специфические исключения для повышения безопасности и удобства отладки.

### Безопасное хранение ключей и защита от атак по сторонним каналам

- **Шифрование приватных ключей:** Приватные ключи шифруются при хранении с использованием ключа, производного от пароля пользователя, обеспечивая дополнительный уровень безопасности.
- **Использование проверенных библиотек:** Все криптографические операции выполняются с использованием проверенных и устойчивых к атакам по сторонним каналам библиотек.

### Управление сессиями и устройствами

- **Управление устройствами:** Пользователи могут просматривать, добавлять и удалять свои устройства, обеспечивая контроль над доступом к аккаунту.
- **Безопасность мультиустройства:** Обеспечена безопасность при использовании нескольких устройств, включая изоляцию ключей и управление сессиями.

## Установка

## Запуск сервера с использованием Docker Compose

Убедитесь, что у вас установлены Docker и Docker Compose.

```bash
docker-compose up --build


```bash
git clone https://github.com/SilentLink-lab/silentlink-protocol.git
cd silentlink-protocol
pip install -r requirements.txt
