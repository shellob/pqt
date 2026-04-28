# pqt — постквантовый токен доступа

Прототип формата **PQ-AT** (Post-Quantum Access Token) — постквантовая
замена JWT с гибридной схемой подписи (ECDSA P-256 + ML-DSA-65) и
компактным CBOR-кодированием. Реализация главы 3 и экспериментальная
база главы 4 магистерской диссертации **«Построение токена постквантового
доступа»** (Тимофеенко С. В., ВГУ ФКН, 2026).

## Зачем

JWT — самый распространённый сегодня формат токена доступа в OAuth, и
подпись там обычно ставится либо на эллиптической кривой (ES256), либо на
RSA. Обе эти схемы математически держатся на задачах, которые квантовый
компьютер достаточного размера решает за полиномиальное время — а значит,
рано или поздно перестанут быть безопасными.

Алгоритм ML-DSA (FIPS 204, 2024) специально стандартизован NIST как
постквантовый аналог ECDSA. Но переход на «чистую» постквантовую схему
рискованный: ML-DSA молодой, у криптоаналитиков было меньше времени найти
в нём слабые места. Поэтому промышленный путь — **гибрид**: подписываем
один и тот же токен сразу двумя ключами, ECDSA и ML-DSA, и принимаем его
только если обе подписи валидны. Если в будущем сломают одну из схем,
вторая всё равно держит.

Этот репозиторий — рабочий прототип такого формата токена, два OAuth-сервера
(авторизация и ресурсы) поверх него, CLI-утилита, эталонный JWT для сравнения
и набор бенчмарков под главы 4.2–4.6 диссертации.

## Что внутри формата

PQ-AT по структуре повторяет JWT (три части `Header.Payload.Signature`),
но заголовок и payload расширены, чтобы поддерживать постквантовые алгоритмы
и компактный бинарный формат:

- **Заголовок (Header)** — служебные поля: `alg` (какой алгоритм подписи),
  `kid` (идентификатор ключа — нужен для плавной ротации, см. ниже), `enc`
  (как закодирован payload — JSON или CBOR), `typ`, `ver`.
- **Payload — claims** — стандартные для JWT поля: `sub` (subject,
  кто пользователь), `iss` (issuer, кто выпустил токен), `aud` (audience,
  кому предназначен), `exp` (expiry, до какого момента валиден),
  `iat` (issued at), `jti` (уникальный id токена), `scope` (список прав
  через пробел: «read write admin»). Дополнительно — `kind`: помечает
  токен как access или refresh, чтобы при отзыве сервер сразу знал, что
  именно отзывать.
- **Подпись** — байты, полученные подписью склейки `Header || Payload`
  приватным ключом. У гибрида сюда кладутся обе подписи подряд.

Дальше формат добавляет три «оси выбора»:

**Алгоритм (поле `alg`):**

- `ecdsa-p256` — классическая ECDSA на кривой P-256. Для обратной
  совместимости и как классическая часть гибрида. Подпись 64–72 байта.
- `mldsa44` / `mldsa65` / `mldsa87` — постквантовая ML-DSA трёх уровней
  стойкости (соответствуют NIST security level 2/3/5). Подписи: 2420 /
  3309 / 4627 байт. Целевой для прототипа — `mldsa65`.
- `hybrid-ecdsa-mldsa44/65/87` — гибрид: на одно сообщение ставятся обе
  подписи, при проверке верификации идут параллельно через `errgroup`.

**Кодек payload (поле `enc`):**

- `json` — стандартный JWT-совместимый путь.
- `cbor` — бинарная альтернатива JSON (RFC 8949). Поля идут с
  целочисленными ключами в стиле CWT (RFC 8392, 1=sub, 2=iss, …) и без
  пробелов и кавычек. На типовых claims даёт 2–20% экономии.

**Формат сериализации:**

- **Текстовый**, совместимый с JWT: `Base64url(H).Base64url(P).Base64url(Sig)`.
  Помещается в HTTP-заголовок `Authorization: Bearer ...`.
- **Бинарный**, компактный: `[2 байта len(H)] H [2 байта len(P)] P Sig`.
  На 25% меньше за счёт устранения накладных расходов Base64url
  (4/3 ≈ 1.33).

Целевой компактный размер постквантового токена при `mldsa65` + CBOR + binary —
около 3.5 КБ. Это укладывается в стандартный лимит HTTP-заголовков 8 КБ
у Apache/Nginx.

Полная спецификация формата — раздел 2 диссертации; архитектура
реализации — [docs/architecture.md](docs/architecture.md).

## Что демонстрирует проект

| Слой | Файлы | Что покрывает |
|---|---|---|
| Криптослой | `keys/` | ECDSA P-256, ML-DSA-44/65/87 через `cloudflare/circl`, гибрид с параллельной верификацией |
| JWK | `jwk/` | сериализация ключей в JSON Web Key + JWK Set, расширения `kty=MLDSA` и `kty=Hybrid` |
| Формат токена | `token/` | заголовок и claims, два кодека (JSON/CBOR), два формата (текст/бинарь) |
| Issue/Validate | корневой `pqt` | публичный API + защиты: проверка `alg` ДО верификации (alg-confusion), обязательный `exp`, отзыв через `IsRevoked` |
| Fuzz-тесты | `pqt/*_fuzz_test.go` | 4 fuzz-цели на разбор text/binary и валидацию |
| CLI | `cmd/pqt-cli` | `keygen` / `sign` / `verify` / `decode` на stdlib `flag`; e2e-матрица 5 alg × 2 codec × 2 format = 20 комбинаций |
| OAuth-сервер | `internal/authserver`, `cmd/pqt-authserver` | password grant, refresh rotation, RFC 7009 revoke, RFC 8414 discovery, JWKS, pprof |
| Resource-сервер | `internal/resourceserver`, `cmd/pqt-resource` | middleware `RequireValidToken` + `RequireScope`, JWKS-клиент с авто-refresh при cache-miss (покрывает ротацию ключей) |
| Web UI | `internal/authserver/webui` | vanilla HTML/JS-страница (login/refresh/revoke/decode), вшита через `//go:embed` |
| Swagger UI | `internal/authserver/webui.go` | offline через `swgui/v5`, без обращений к CDN |
| OpenAPI 3.1 | `internal/openapi`, `cmd/pqt-openapi-gen` | code-first; YAML генерится в `api/openapi.yaml` и в embed для сервера |
| Эталонный JWT | `internal/jwtbase` | `golang-jwt/jwt/v5` с фиксированным ES256 — точка отсчёта для главы 4.3 |
| Бенчмарки | `internal/bench`, `keys/hybrid_test.go`, `token/cbor_libs_bench_test.go` | главы 4.2–4.6: производительность ML-DSA, PQ-AT vs JWT, hybrid seq vs parallel, формат-матрица, нагрузочное тестирование через `vegeta` |

Все 14 этапов плана из [docs/plan.md](docs/plan.md) закрыты.

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
└── docs/
    ├── plan.md              # план работы (14 этапов)
    ├── architecture.md      # архитектурный документ для раздела 3.1 ВКР
    ├── bench_crypto.md      # цифры для глав 4.2, 4.3, 4.4
    ├── bench_format_matrix.md  # цифры для главы 4.5
    ├── bench_cbor_libs.md   # сравнение CBOR-либ для главы 4.5
    └── bench_load.md        # шаблон таблиц и инструкции для главы 4.6
```

## Быстрый старт

Минимум, чтобы убедиться, что всё работает локально:

```bash
# 1. Прогнать все тесты
go test ./...

# 2. Поднять auth-сервер
go run ./cmd/pqt-authserver
```

После второй команды открой <http://localhost:8080/> — там форма
логина / refresh / revoke / decode и кнопки JWKS / discovery. На
<http://localhost:8080/docs/> лежит интерактивный Swagger UI.

Seed-пользователи (хардкод в коде, для демо):

| Логин | Пароль | scope |
|---|---|---|
| `alice` | `alice-password-2026` | `read write` |
| `bob` | `bob-password-2026` | `read` |
| `charlie` | `charlie-password-2026` | `read write admin` |
| `dave` | `dave-password-2026` | `read` |

## Запуск всех сценариев

### Полный сценарий с двумя серверами

Терминал 1 — сервер авторизации (выпускает токены):

```bash
go run ./cmd/pqt-authserver
```

Терминал 2 — сервер ресурсов (проверяет токены и пускает на защищённые
эндпоинты):

```bash
PQT_AUTH_BASE_URL=http://localhost:8080 \
PQT_RESOURCE_ISSUER=http://localhost:8080 \
PQT_RESOURCE_AUDIENCE=http://localhost:8080 \
go run ./cmd/pqt-resource
```

Терминал 3 — обращения к API:

```bash
# Получить пару access + refresh (без jq — сразу глазами видно)
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

Все четыре подкоманды работают с любым алгоритмом из формата (`ecdsa-p256`,
`mldsa44/65/87`, `hybrid-ecdsa-mldsa44/65/87`) и любым сочетанием кодек ×
формат:

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

# 5. Посмотреть содержимое без проверки подписи (для отладки)
go run ./cmd/pqt-cli decode --token token.txt
```

У каждой подкоманды есть `-h` со справкой по флагам.

### Нагрузочный прогон (для главы 4.6)

Сервер должен быть запущен с включённым профайлером — иначе эндпоинты
`/debug/pprof/*` отключены:

```bash
go run ./cmd/pqt-authserver --debug

# В другом терминале — два сценария
go run ./cmd/pqt-loadtest --scenario token --rate 100 --duration 30s
go run ./cmd/pqt-loadtest --scenario me    --rate 500 --duration 30s

# Параллельно — снять CPU-профиль
go tool pprof -http=:6060 http://localhost:8080/debug/pprof/profile?seconds=30
```

Сценарий `token` грузит выпуск токенов (узкое место — bcrypt при
проверке пароля), сценарий `me` грузит проверку токенов на
resource-сервере (узкое место — верификация подписи). Подробнее —
[docs/bench_load.md](docs/bench_load.md).

### Регенерация OpenAPI-спецификации

Делается после правок в `internal/openapi/spec.go`:

```bash
go run ./cmd/pqt-openapi-gen
```

Команда обновляет два файла одновременно:
[`api/openapi.yaml`](api/openapi.yaml) (для документации) и
`internal/authserver/webui/openapi.yaml` (для embed в auth-сервер,
чтобы Swagger UI не ходил никуда лишнего).

### Бенчмарки

```bash
# Криптопримитивы (главы 4.2, 4.4)
go test -bench=. -benchmem -run=^$ -benchtime=2s ./keys/...

# PQ-AT vs JWT (глава 4.3)
go test -bench=. -benchmem -run=^$ -benchtime=2s ./internal/bench/...

# Сравнение CBOR-либ — fxamacker/cbor vs ugorji/go (глава 4.5)
go test -bench=BenchmarkCBOR -benchmem -run=^$ -benchtime=2s ./token/...

# Размеры токенов в виде таблиц
go test -v -run=TestFormatMatrix_Sizes ./internal/bench/...
go test -v -run=TestPQATvsJWT_Sizes    ./internal/bench/...
go test -v -run=TestMLDSASignatureSizes ./keys/...
```

Полные таблицы результатов — в `docs/bench_*.md`.

### Fuzz-тесты

Каждая цель поднимает рандомные входы на 30 секунд и проверяет, что парсер
не падает с panic'ом и не возвращает чушь:

```bash
go test -run=^$ -fuzz=FuzzParseText      -fuzztime=30s .
go test -run=^$ -fuzz=FuzzParseBinary    -fuzztime=30s .
go test -run=^$ -fuzz=FuzzValidateText   -fuzztime=30s .
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
| `PQT_REFRESH_TTL` | `720h` | время жизни refresh-токена (30 дней) |
| `PQT_GENERATE_ALG` | `hybrid-ecdsa-mldsa65` | алгоритм для авто-генерации ключа на первом старте |
| `PQT_BCRYPT_COST` | `10` | сложность bcrypt для seed-юзеров (≈60 мс на проверку) |
| `PQT_DEBUG` | `0` | включить `/debug/pprof/*` (то же что `--debug`) |

### `pqt-resource`

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PQT_RESOURCE_ADDR` | `:8081` | адрес для Listen |
| `PQT_AUTH_BASE_URL` | `http://localhost:8080` | базовый URL `pqt-authserver` для скачивания JWKS |
| `PQT_RESOURCE_ISSUER` | `=AUTH_BASE_URL` | ожидаемое значение `iss` |
| `PQT_RESOURCE_AUDIENCE` | (пусто) | ожидаемое значение `aud` (если пусто, проверка пропускается) |
| `PQT_RESOURCE_LEEWAY` | `0s` | допустимая разница часов с auth-сервером |
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
