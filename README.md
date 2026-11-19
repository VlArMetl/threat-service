# Threat Information Exchange Service

REST-сервис для обмена информацией об угрозах по MD5-хешу файла.
API описан в [api/openapi.yaml](api/openapi.yaml).

## Возможности

- `GET /info/{md5}`: получить угрозу.
- `POST /info`: создать угрозу (MD5 уникален, регистр не важен).
- `PUT /info/{md5}`: полностью заменить данные угрозы.
- Модель угрозы дополнена полями `severity` (`low` / `medium` / `high` / `critical`), `description`, `created_at`, `updated_at`.
- Валидация: формат MD5, обязательное непустое `name` (до 256 байт), допустимое `severity`, `description` до 2000 байт, неизвестные поля запрещены, тело не больше 1 МБ.
- Хранилище: PostgreSQL или память процесса, если `DATABASE_URL` не задан.
- Код HTTP-слоя (типы и маршруты) генерируется из спецификации с помощью [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen).
- Защита:
  - API-ключи с правами на чтение и запись;
  - rate-limit по IP;
  - HTTPS;
  - таймауты сервера;
  - корректная остановка (graceful shutdown).

## Быстрый старт (Docker)

```bash
docker compose up -d --build
```

Поднимутся PostgreSQL и сервис на `http://localhost:8080` с ключами по умолчанию: `dev-write-key` (полный доступ) и `dev-read-key` (только чтение). Ключи переопределяются переменными `API_KEYS` и `READ_API_KEYS`.

```bash
curl -i -X POST http://localhost:8080/info \
  -H "X-API-Key: dev-write-key" -H "Content-Type: application/json" \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"high"}'

curl -i http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e -H "X-API-Key: dev-read-key"
```

В PowerShell используйте `curl.exe`, а JSON удобнее передавать из файла: `-d "@threat.json"`.

Остановить: `docker compose down`. Чтобы удалить и данные базы: `docker compose down -v`.

## Локальный запуск

```bash
go run ./cmd/server
```

Без переменных окружения сервис хранит данные в памяти, а авторизация отключена (в лог выводится предупреждение).

## Конфигурация

| Переменная | По умолчанию | Описание |
|---|---|---|
| `ADDR` | `:8080` | Адрес сервера |
| `DATABASE_URL` | — | Строка подключения к PostgreSQL. Если пусто, данные хранятся в памяти |
| `API_KEYS` | — | Ключи с полным доступом, через запятую |
| `READ_API_KEYS` | — | Ключи только для чтения (GET), через запятую |
| `RATE_LIMIT_RPS` | `10` | Средний лимит запросов в секунду с одного IP |
| `RATE_LIMIT_BURST` | `20` | Допустимый всплеск запросов |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | — | Сертификат и ключ. Если заданы, сервер работает по HTTPS (TLS 1.2+) |

Если ни один ключ не задан, авторизация отключена.

## Защита

- **Авторизация.** Ключ передаётся в заголовке `X-API-Key`. Без ключа или с неверным ключом сервис отвечает `401`. Ключ только для чтения на `POST`/`PUT` получает `403`. Ключи сравниваются за постоянное время.
- **Rate-limit.** Token bucket на каждый IP. При превышении сервис отвечает `429` с заголовком `Retry-After`. Лимит проверяется до авторизации, поэтому подбор ключей тоже ограничен. Заголовку `X-Forwarded-For` сервис не доверяет.
- **HTTPS.** Самоподписанный сертификат для проверки можно сделать так:
  ```bash
  go run "$(go env GOROOT)/src/crypto/tls/generate_cert.go" --host localhost
  TLS_CERT_FILE=cert.pem TLS_KEY_FILE=key.pem go run ./cmd/server
  curl --cacert cert.pem https://localhost:8080/info/...
  ```
- **Прочее.**
  - Таймауты чтения и записи защищают от медленных клиентов (slowloris).
  - Тело запроса ограничено 1 МБ.
  - Клиенту при `500` не отдаются внутренние детали ошибки.
  - Контейнер собран на distroless-образе и работает от непривилегированного пользователя.

## Тесты

```bash
go test ./...
```

- `internal/model`: юнит-тесты валидации.
- `internal/storage`: общий набор проверок для любой реализации `Storage`. Для памяти он запускается всегда.
- `internal/handler`: HTTP-тесты обработчиков через `httptest`.
- `internal/middleware`: авторизация и rate-limit.
- `internal/app`: интеграционный тест всей цепочки (rate-limit → авторизация → обработчики → хранилище).

Интеграционный тест с PostgreSQL запускается, если задан `TEST_DATABASE_URL`. **Тест очищает таблицу `threats`!**

```bash
docker compose up -d db
TEST_DATABASE_URL="postgres://threats:threats@localhost:5432/threats?sslmode=disable" go test ./internal/storage/
```

## Кодогенерация

Типы запросов и ответов, интерфейс `ServerInterface` и маршруты лежат в `internal/api/api.gen.go`. Этот файл генерируется из спецификации и вручную не редактируется. После изменения `api/openapi.yaml`:

```bash
go generate ./...
```

Генератор подключён как инструмент модуля (`tool` в `go.mod`), отдельно ставить его не нужно.

## Структура

```
api/                  OpenAPI-спецификация и конфиг генератора
cmd/server/           точка входа
internal/api/         сгенерированный HTTP-слой
internal/app/         конфигурация и сборка сервиса
internal/handler/     обработчики, реализуют api.ServerInterface
internal/middleware/  авторизация и rate-limit
internal/model/       модель угрозы и валидация
internal/respond/     отправка JSON-ответов
internal/storage/     интерфейс Storage, реализации в памяти и в PostgreSQL
```

Слои разделены так:
- `model` не знает про HTTP и базу данных;
- `storage` работает только с `model`;
- `handler` переводит HTTP-типы из спецификации в модель и обратно.
