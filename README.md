# SilentLink — Протокол Безопасного Обмена Сообщениями

Пожертвования
Если вы хотите поддержать развитие проекта, вы можете сделать пожертвование на следующие кошельки:

Bitcoin: 1GYpJpKSi1Sn7LXexYfva8Yvu5u7WkwJbo

ETH ERC20: 0x7b6da964518b161ea8b2f1d83f12f99615380984

USDT TRC20: TLLx5Pie2BDkRbDRxTxBa28YTaMgg7uuzr

Dogecoin: DEs46phF9Sa1ReNSD853TzLcg9JkxfWeQL

## Описание

**SilentLink** — это современный протокол сквозного шифрования, разработанный для обеспечения **безопасного** и **приватного** обмена сообщениями в режиме реального времени. Он создан с целью максимальной защиты данных пользователей, используя **постквантовые криптографические алгоритмы**, и предоставляет функциональность для безопасных групповых чатов и поддержки нескольких устройств.

## Особенности

- **Постквантовая безопасность:** Использует алгоритмы, устойчивые к квантовым атакам, такие как **CRYSTALS-Kyber** для обмена ключами.
- **Сквозное шифрование:** Обеспечивает конфиденциальность сообщений от отправителя до получателя.
- **Совершенная прямая секретность (PFS):** Компрометация текущих ключей не раскрывает прошлые сообщения.
- **Поддержка нескольких устройств:** Пользователь может использовать несколько устройств одновременно с безопасной синхронизацией.
- **Групповые чаты:** Безопасный групповой обмен сообщениями.
- **Сокрытие метаданных:** Реализованы методы обфускации метаданных для повышения конфиденциальности.
- **Правдоподобное отрицание:** Отправитель может отрицать факт отправки конкретного сообщения.
- **Открытый исходный код:** Проект открыт для сообщества и доступен для аудита.

## Обновления и улучшения

### 1. Переход на постквантовую безопасность с использованием Kyber

- **Замена x25519 на Kyber:**
  - Обновлен алгоритм обмена ключами, заменив **x25519** на постквантовый алгоритм **CRYSTALS-Kyber**.
  - Это обеспечивает устойчивость протокола к атакам квантовых компьютеров и повышает общую безопасность системы.

- **Обновление криптографических примитивов:**
  - Добавлены функции для генерации и использования ключей Kyber.
  - Реализованы функции инкапсуляции и декапсуляции сессий с использованием Kyber512 из библиотеки `pykyber`.
  - Обновлены функции шифрования и расшифровки данных, сохраняя использование ChaCha20-Poly1305 для симметричного шифрования.

- **Модификация протокола Double Ratchet:**
  - Заменены операции Диффи-Хеллмана на операции с использованием Kyber.
  - Обновлены механизмы генерации корневых и цепных ключей для обеспечения постквантовой безопасности.

### 2. Оптимизация серверной архитектуры с использованием FastAPI

- **Переход на FastAPI и Redis:**
  - Серверная часть переписана с использованием **FastAPI** и **Redis** для повышения производительности и масштабируемости.
  - FastAPI обеспечивает высокую производительность и поддержку асинхронных операций.
  - Redis используется для хранения состояния, управления активными соединениями и обмена сообщениями между серверами при горизонтальном масштабировании.

- **Асинхронная обработка:**
  - Сервер теперь использует асинхронные функции и обработчики для эффективного управления соединениями.
  - Улучшена отзывчивость сервера и снижены задержки при обработке сообщений.

- **Docker и Docker Compose:**
  - Добавлена поддержка **Docker** и **Docker Compose** для облегчения развёртывания и масштабирования.
  - Простое развёртывание сервера и связанных сервисов с помощью Docker Compose.

- **Горизонтальное масштабирование:**
  - Возможность запуска нескольких экземпляров сервера и распределения нагрузки.
  - Обеспечена высокая доступность и возможность масштабирования по мере роста числа пользователей.

### 3. Обфускация метаданных и улучшение конфиденциальности

- **Паддинг сообщений:**
  - Реализован механизм дополнения сообщений случайными данными до фиксированного размера для сокрытия реальной длины сообщений.
  - Это затрудняет анализ трафика и улучшает конфиденциальность общения.

- **Фиктивные сообщения:**
  - Добавлена функция периодической отправки фиктивных сообщений для обфускации трафика.
  - Фиктивные сообщения помогают скрыть реальные паттерны общения.

- **Фиксированные интервалы отправки:**
  - Отправка сообщений осуществляется через случайные или фиксированные промежутки времени.
  - Усложняет определение активности пользователей по временным меткам.

### 4. Оптимизация алгоритмов и операций

- **Аппаратные ускорения:**
  - Проверка и использование аппаратных ускорений для криптографии при доступности.
  - Повышает производительность криптографических операций.

- **Эффективные алгоритмы:**
  - Оптимизация криптографических операций для снижения нагрузки на процессор.
  - Улучшена обработка ошибок и логирование для облегчения отладки и мониторинга.

## Установка

**Примечание:** Убедитесь, что у вас установлены все необходимые зависимости, включая `cryptography`, `asyncio`, `fastapi`, `uvicorn` и `redis`. Установите библиотеку `pykyber` для поддержки постквантовых алгоритмов.

### Клонирование репозитория и установка зависимостей

```bash
git clone https://github.com/SilentLink-lab/silentlink-protocol.git
cd silentlink-protocol
pip install -r requirements.txt
