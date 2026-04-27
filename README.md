# pqt — постквантовый токен доступа

Прототип формата **PQ-AT** (Post-Quantum Access Token) — постквантовая замена
JWT с гибридной схемой подписи (ECDSA P-256 + ML-DSA-65) и компактным
CBOR-кодированием.

Реализация главы 3 и экспериментальная база главы 4 магистерской диссертации
**«Построение токена постквантового доступа»** (Тимофеенко С. В., ВГУ ФКН, 2026).

## О формате

PQ-AT по структуре повторяет JWT (`Header.Payload.Signature`), но добавляет:

- **Три режима подписи**, переключаемые полем `alg` в заголовке:
  - `ecdsa-p256` — классическая ECDSA на кривой P-256 (для обратной
    совместимости и в качестве классической части гибрида);
  - `mldsa44` / `mldsa65` / `mldsa87` — постквантовая ML-DSA трёх уровней
    стойкости (FIPS 204), целевой — `mldsa65`;
  - `hybrid-ecdsa-mldsa44/65/87` — гибрид с двумя подписями над одним
    сообщением и параллельной верификацией (целевой — `hybrid-ecdsa-mldsa65`).
- **Два кодека payload**: JSON со строковыми именами полей (RFC 7519)
  или CBOR с целочисленными ключами в стиле CWT (RFC 8392).
- **Два формата сериализации**: текстовый, совместимый с JWT
  (`Base64url(H).Base64url(P).Base64url(Sig)`), или компактный бинарный
  (`[2 байта длины H] H [2 байта длины P] P [подпись]`) — на 25% меньше
  по размеру за счёт устранения накладных расходов Base64url.

Целевой компактный размер постквантового токена при CBOR + binary —
около 3.5 КБ (укладывается в стандартные ограничения HTTP-заголовков
8 КБ у Apache/Nginx).

Полная спецификация формата — раздел 2 диссертации;
архитектура реализации — [docs/architecture.md](docs/architecture.md).

## Состояние

План работы (14 этапов) закрыт целиком. Прогресс — [docs/plan.md](docs/plan.md).

## Стек

| Компонент | Использование |
|---|---|
| Go 1.26 | язык реализации |
| `crypto/ecdsa` | классическая ECDSA P-256 |
| `github.com/cloudflare/circl` | ML-DSA (FIPS 204), уровни 44/65/87 |
| `github.com/fxamacker/cbor/v2` | CBOR-кодек (RFC 8949), CWT-стиль (RFC 8392) |
| `golang.org/x/crypto/bcrypt` | хеширование паролей seed-юзеров на сервере |
| `net/http` | HTTP без сторонних фреймворков, паттерны Go 1.22 mux |
| `log/slog` | структурированное логирование |
| `github.com/golang-jwt/jwt/v5` | эталонный JWT для сравнения в главе 4.3 |
| `github.com/getkin/kin-openapi` | code-first генератор OpenAPI 3.1 |
| `github.com/swaggest/swgui` | offline-сборка Swagger UI с встроенными ассетами |
| `github.com/tsenart/vegeta/v12` | нагрузочные сценарии для главы 4.6 |

## Структура

```
pqt/
├── doc.go                   # корневой пакет — публичный API Issue/Parse/Validate
├── issuer.go                # Issue
├── validator.go             # Parse + Validate
├── options.go               # IssueOptions, ValidateOptions, KeySource, Clock
├── errors.go                # маркерные ошибки публичного API
│
├── keys/                    # криптослой
│   ├── alg.go               #   тип Alg + константы алгоритмов
│   ├── signer.go            #   интерфейсы PrivateKey/PublicKey
│   ├── ecdsa.go             #   ECDSA P-256
│   ├── mldsa.go             #   ML-DSA через cloudflare/circl
│   └── hybrid.go            #   гибрид с параллельной verify
│
├── jwk/                     # JSON Web Key
│   ├── jwk.go               #   тип JWK + Marshal/Parse Public/Private
│   ├── jwk_set.go           #   тип Set (RFC 7517 §5) + Find(kid)
│   └── ec.go, mldsa.go, hybrid.go
│
├── token/                   # формат токена (без подписи)
│   ├── header.go            #   Header{Alg, Ver, Typ, Enc, Kid}
│   ├── claims.go            #   Claims{Sub, Iss, Aud, Exp, Iat, Jti, Scope, Kind}
│   ├── codec_payload.go     #   EncodePayload/DecodePayload (JSON, CBOR)
│   ├── format_text.go       #   текстовый JWT-совместимый формат
│   └── format_binary.go     #   компактный бинарный формат
│
├── internal/                # внутренние пакеты, не импортируются извне
│   ├── authserver/          #   сервер авторизации с Web UI и Swagger UI
│   ├── resourceserver/      #   middleware-валидация Bearer-токена
│   ├── jwtbase/             #   эталонный JWT для главы 4.3
│   ├── openapi/             #   code-first генератор OpenAPI 3.1
│   └── bench/               #   сравнительные бенчмарки и smoke-нагрузка
│
├── cmd/                     # бинарники
│   ├── pqt-cli/             #   CLI: keygen / sign / verify / decode
│   ├── pqt-authserver/      #   сервер авторизации
│   ├── pqt-resource/        #   демо-сервер ресурсов
│   ├── pqt-openapi-gen/     #   генератор api/openapi.yaml
│   └── pqt-loadtest/        #   нагрузочные сценарии через vegeta
│
├── api/
│   └── openapi.yaml         # сгенерированная OpenAPI 3.1-спецификация
│
├── docs/
│   ├── plan.md              # план работы (14 этапов)
│   ├── architecture.md      # архитектурный документ для раздела 3.1 ВКР
│   ├── bench_crypto.md      # цифры для глав 4.2, 4.3, 4.4
│   ├── bench_format_matrix.md  # цифры для главы 4.5
│   ├── bench_cbor_libs.md   # сравнение CBOR-либ для главы 4.5
│   └── bench_load.md        # шаблон таблиц и инструкции для главы 4.6
│
└── test/                    # вспомогательные тестовые сценарии (если появятся)
```

## Запуск

### Минимальная проверка — все тесты

```bash
go test ./...
```

Должно показать `ok` для всех 11 пакетов
(`pqt`, `pqt/keys`, `pqt/jwk`, `pqt/token`, `pqt/cmd/pqt-cli`,
`pqt/internal/authserver`, `pqt/internal/resourceserver`, `pqt/internal/jwtbase`,
`pqt/internal/openapi`, `pqt/internal/bench`).

### Демо в браузере

В одном терминале запусти сервер авторизации:

```bash
go run ./cmd/pqt-authserver
```

Открой в браузере:

| Адрес | Что покажет |
|---|---|
| <http://localhost:8080/> | главную страницу демо с формами login / refresh / revoke / decode + кнопками JWKS и discovery |
| <http://localhost:8080/docs/> | Swagger UI с интерактивной документацией всех эндпоинтов |
| <http://localhost:8080/.well-known/pq-jwks> | JWK Set с публичными ключами сервера |
| <http://localhost:8080/.well-known/oauth-authorization-server> | метаданные сервера по RFC 8414 |

В seed-наборе четыре пользователя:
`alice`/`alice-password-2026` (scope `read write`),
`bob`/`bob-password-2026` (`read`),
`charlie`/`charlie-password-2026` (`read write admin`),
`dave`/`dave-password-2026` (`read`).

### Полный сценарий с двумя серверами

Терминал 1 — сервер авторизации:

```bash
go run ./cmd/pqt-authserver
```

Терминал 2 — сервер ресурсов:

```bash
PQT_AUTH_BASE_URL=http://localhost:8080 \
PQT_RESOURCE_ISSUER=http://localhost:8080 \
PQT_RESOURCE_AUDIENCE=http://localhost:8080 \
go run ./cmd/pqt-resource
```

Терминал 3 — обращения к API:

```bash
# Получить пару access + refresh
curl -s -X POST http://localhost:8080/auth/token \
  -d "grant_type=password&username=charlie&password=charlie-password-2026"

# Дёрнуть защищённый эндпоинт
ACCESS=$(curl -s -X POST http://localhost:8080/auth/token \
  -d "grant_type=password&username=charlie&password=charlie-password-2026" \
  | jq -r .access_token)

curl -s http://localhost:8081/me     -H "Authorization: Bearer $ACCESS"
curl -s http://localhost:8081/admin  -H "Authorization: Bearer $ACCESS"
```

### Через CLI без сервера

```bash
# 1. Сгенерировать пару ключей
go run ./cmd/pqt-cli keygen --alg hybrid-ecdsa-mldsa65 --kid demo-1 --out ./demo-keys

# 2. Файл claims.json
cat > claims.json <<'EOF'
{
  "sub": "user-42",
  "iss": "https://my-server.example",
  "aud": "https://my-api.example",
  "iat": 1745596800,
  "exp": 1893456000,
  "jti": "demo-token-1",
  "scope": "read write"
}
EOF

# 3. Выпустить токен
go run ./cmd/pqt-cli sign \
  --key ./demo-keys/demo-1.priv.jwk.json \
  --claims claims.json \
  --out token.txt

# 4. Проверить
go run ./cmd/pqt-cli verify \
  --key ./demo-keys/demo-1.pub.jwk.json \
  --token token.txt

# 5. Посмотреть содержимое без проверки
go run ./cmd/pqt-cli decode --token token.txt
```

Подкоманды CLI: `keygen`, `sign`, `verify`, `decode`. У каждой есть `-h`
со справкой по флагам.

### Нагрузочный прогон (для главы 4.6)

```bash
# Сервер с включённым профайлером
go run ./cmd/pqt-authserver --debug

# В другом терминале
go run ./cmd/pqt-loadtest --scenario token --rate 100 --duration 30s
go run ./cmd/pqt-loadtest --scenario me    --rate 500 --duration 30s

# Параллельно — CPU-профиль
go tool pprof -http=:6060 http://localhost:8080/debug/pprof/profile?seconds=30
```

Подробнее — [docs/bench_load.md](docs/bench_load.md).

### Регенерация OpenAPI-спецификации

После любых правок в `internal/openapi/spec.go`:

```bash
go run ./cmd/pqt-openapi-gen
```

Команда обновляет два файла одновременно:
[`api/openapi.yaml`](api/openapi.yaml) (для документации) и
`internal/authserver/webui/openapi.yaml` (для embed в сервер).

### Бенчмарки

```bash
# Криптопримитивы (главы 4.2, 4.4)
go test -bench=. -benchmem -run=^$ -benchtime=2s ./keys/...

# PQ-AT vs JWT (глава 4.3)
go test -bench=. -benchmem -run=^$ -benchtime=2s ./internal/bench/...

# Сравнение CBOR-либ (глава 4.5)
go test -bench=BenchmarkCBOR -benchmem -run=^$ -benchtime=2s ./token/...

# Размеры токенов
go test -v -run=TestFormatMatrix_Sizes ./internal/bench/...
go test -v -run=TestPQATvsJWT_Sizes    ./internal/bench/...
go test -v -run=TestMLDSASignatureSizes ./keys/...
```

Полные таблицы результатов — в `docs/bench_*.md`.

### Fuzz-тесты

```bash
go test -run=^$ -fuzz=FuzzParseText    -fuzztime=30s .
go test -run=^$ -fuzz=FuzzParseBinary  -fuzztime=30s .
go test -run=^$ -fuzz=FuzzValidateText -fuzztime=30s .
go test -run=^$ -fuzz=FuzzValidateBinary -fuzztime=30s .
```

### Линт и форматирование

```bash
golangci-lint run ./...
gofmt -s -w .
go mod tidy
```

## Конфигурация серверов

### `pqt-authserver`

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PQT_ADDR` | `:8080` | адрес для Listen |
| `PQT_ISSUER` | `http://localhost:8080` | значение поля `iss` в выпускаемых токенах |
| `PQT_KEYS_DIR` | `./keys` | директория с приватными ключами JWK |
| `PQT_DEFAULT_KID` | первый по алфавиту | какой ключ использовать для подписи |
| `PQT_ACCESS_TTL` | `15m` | время жизни access-токена |
| `PQT_REFRESH_TTL` | `720h` | время жизни refresh-токена |
| `PQT_GENERATE_ALG` | `hybrid-ecdsa-mldsa65` | алгоритм для авто-генерации ключа на первом старте |
| `PQT_BCRYPT_COST` | `10` | сложность bcrypt для seed-юзеров |
| `PQT_DEBUG` | `0` | включить `/debug/pprof/*` (то же что `--debug`) |

### `pqt-resource`

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PQT_RESOURCE_ADDR` | `:8081` | адрес для Listen |
| `PQT_AUTH_BASE_URL` | `http://localhost:8080` | базовый URL `pqt-authserver` для скачивания JWKS |
| `PQT_RESOURCE_ISSUER` | `=AUTH_BASE_URL` | ожидаемое значение `iss` |
| `PQT_RESOURCE_AUDIENCE` | (пусто) | ожидаемое значение `aud` (если пусто, проверка пропускается) |
| `PQT_RESOURCE_LEEWAY` | `0s` | допуск рассинхронизации часов |
| `PQT_RESOURCE_JWKS_REFRESH` | `5m` | интервал фонового обновления JWKS |
| `PQT_RESOURCE_HTTP_TIMEOUT` | `5s` | таймаут на JWKS-запросы |

## Установка инструментов

```bash
go install golang.org/x/tools/gopls@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

## Документация

| Документ | О чём |
|---|---|
| [docs/plan.md](docs/plan.md) | план реализации в 14 этапов |
| [docs/architecture.md](docs/architecture.md) | архитектура комплекса (для раздела 3.1 ВКР) |
| [docs/bench_crypto.md](docs/bench_crypto.md) | цифры для глав 4.2, 4.3, 4.4 |
| [docs/bench_format_matrix.md](docs/bench_format_matrix.md) | формат-матрица для главы 4.5 |
| [docs/bench_cbor_libs.md](docs/bench_cbor_libs.md) | сравнение CBOR-либ для главы 4.5 |
| [docs/bench_load.md](docs/bench_load.md) | шаблоны таблиц и pprof для главы 4.6 |
| [api/openapi.yaml](api/openapi.yaml) | сгенерированная OpenAPI 3.1-спецификация |

## Лицензия

Внутренний проект диссертационной работы. Лицензия не определена.
