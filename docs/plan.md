# План реализации проекта pqt

> Реализация формата **PQ-AT (Post-Quantum Access Token)** с гибридной схемой подписи (ECDSA P-256 + ML-DSA-65) и компактным CBOR-кодированием. Основано на спецификации, описанной в магистерской диссертации С. В. Тимофеенко (ВГУ ФКН, 2026), главы 2–4.

## 1. Архитектурные решения

| Решение | Значение | Обоснование |
|---|---|---|
| **Архитектура** | Library-first, плоский корень | Идиоматично для Go-крипто-библиотек (`crypto/tls`, `golang-jwt/jwt`, `o1egl/paseto`); компактные листинги в приложении А диссертации |
| **Layout** | `pqt/` (пакет) + `cmd/*` (исполняемые) + `docs/` + `test/` | Минимум вложенности; тесты `*_test.go` рядом с исходниками |
| **Версия Go** | 1.26 | Текущий стабильный toolchain |
| **HTTP** | `net/http` стандартной библиотеки | Без `chi/gin/echo` — не нужны для прототипа |
| **Логирование** | `log/slog` стандартной библиотеки | Структурированное, без зависимостей |
| **CBOR** | `github.com/fxamacker/cbor/v2` | Лидер по производительности; `github.com/ugorji/go/codec` подключается только для сравнительного бенчмарка в гл. 4.5 |
| **JWT-эталон** | `github.com/golang-jwt/jwt/v5` | Де-факто стандарт; используется только для сравнения в гл. 4.3 |
| **ML-DSA** | `github.com/cloudflare/circl/sign/mldsa/{mldsa44,mldsa65,mldsa87}` | Production-ready Go-реализация FIPS 204 |
| **ECDSA** | `crypto/ecdsa` + кривая P-256 | Стандартная библиотека |
| **Нагрузочное** | `github.com/tsenart/vegeta/v12` | Готовые гистограммы и метрики для гл. 4.6 |
| **Хранилище** | In-memory (`sync.Map` / `map`+`sync.RWMutex`) | Достаточно для прототипа; БД усложнила бы воспроизводимость эксперимента |
| **Линтер** | `golangci-lint` v2 (govet, staticcheck, errcheck, gosec, revive, gocyclo) | Стандарт Go-экосистемы |
| **Тесты** | `testing` стандартной библиотеки + native fuzz/benchmark | Сторонние ассерт-библиотеки не нужны |
| **OpenAPI** | OpenAPI 3.1 YAML + Swagger UI (embed) | Спецификация в `api/openapi.yaml`, встроенный Swagger UI на сервере |
| **Web UI** | Native HTML/JS, embed через `embed.FS` | Без фреймворков; формы выпуска, верификации и декода токена |

## 2. Структура каталогов

```
pqt/
├── go.mod / go.sum
├── .golangci.yml
├── .gitignore / .gitattributes
├── README.md
│
├── docs/
│   ├── plan.md                # этот файл
│   └── architecture.md        # черновик раздела 3.1 диссертации (этап 13)
│
├── api/
│   └── openapi.yaml           # OpenAPI 3.1 спецификация (этап 9)
│
├── webui/                     # ассеты для Web UI (этап 10)
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── doc.go                     # пакетный doc-комментарий
├── token.go                   # публичный API: Issue, Parse, Validate
├── claims.go
├── header.go
├── alg.go
├── sign_ecdsa.go
├── sign_mldsa.go              # обёртки над ML-DSA-44/65/87
├── sign_hybrid.go             # параллельная верификация
├── codec_json.go
├── codec_cbor.go              # CWT-маппинг целочисленных ключей
├── format_text.go             # base64url(H).base64url(P).base64url(Sig)
├── format_binary.go           # uint16 lenH | H | uint16 lenP | P | Sig
├── jwk.go                     # JWK + ротация ключей через kid
├── *_test.go                  # юнит-тесты + бенчмарки + fuzz рядом с исходниками
│
├── cmd/
│   ├── pqt-cli/main.go        # этап 6: keygen / sign / verify / decode
│   ├── pqt-authserver/main.go # этап 7
│   ├── pqt-resource/main.go   # этап 8
│   └── pqt-bench/main.go      # этап 12: сценарии гл. 4
│
└── test/
    ├── e2e/                   # E2E через httptest
    └── load/                  # vegeta-сценарии для гл. 4.6
```

## 3. Скоуп функционала

### 3.1. Базовый формат и сервер
- 3 режима подписи: `ecdsa-p256` / `mldsa65` / `hybrid-ecdsa-mldsa65`
- 2 кодека claims: JSON и CBOR (с CWT-маппингом)
- 2 формата токена: текстовый JWT-совместимый и бинарный length-prefix
- Сервер авторизации с эндпоинтами `/auth/token`, `/auth/refresh`, `/.well-known/pq-jwks`
- Эталонный JWT для сравнения в гл. 4

### 3.2. Расширения
1. Демо-сервер ресурсов с middleware-валидатором
2. CLI-утилита `pqt` (keygen / sign / verify / decode)
3. Все три уровня ML-DSA: 44, 65, 87 — расширенное сравнение в гл. 4.2
4. Ротация ключей через `kid` + JWKS с несколькими активными ключами
5. Параллельная верификация в гибриде (`errgroup`) — отдельная подсекция гл. 4
6. Fuzz-тесты парсеров текстового и бинарного форматов
7. Refresh token rotation
8. Token revocation (RFC 7009): `POST /auth/revoke` + список отозванных `jti`
9. OAuth Discovery (RFC 8414): `/.well-known/oauth-authorization-server`
10. pprof-эндпоинт для CPU/heap-профилирования; графики в гл. 4.6
11. Сравнение CBOR-библиотек (`fxamacker/cbor/v2` vs `ugorji/go/codec`) для гл. 4.5
12. Web UI для демо: формы выпуска/верификации, декодер токена
13. OpenAPI 3.1 + Swagger UI (embed)

## 4. Этапы

### Этап 0 — Фундамент
- `go.mod` (модуль `pqt`, Go 1.26)
- Структура каталогов (`cmd/`, `docs/`, `api/`, `webui/`, `test/`)
- `.golangci.yml`, `.gitignore`, `.gitattributes`
- `README.md`

### Этап 1 — Криптослой
- `signer.go`: интерфейсы `Signer`, `Verifier`, `KeyPair`
- `sign_ecdsa.go`: P-256 обёртка, ASN.1 формат подписи (~70–72 байта)
- `sign_mldsa.go`: обёртки над `circl/sign/mldsa/{mldsa44,mldsa65,mldsa87}`, единый интерфейс
- `sign_hybrid.go`: композиция `ECDSA + ML-DSA`, layout `ECDSA || uint16-len-ECDSA || ML-DSA`, параллельная верификация через `errgroup`, флаг последовательного режима для бенча
- Тесты: round-trip, tampering, неверный ключ, корректный размер подписи
- Бенчмарки: `Benchmark_*_Keygen / _Sign / _Verify` для всех вариантов

### Этап 2 — Формат токена
- `header.go`: структура `Header{Alg, Ver, Typ, Enc, Kid}`
- `claims.go`: структура `Claims{Sub, Iss, Aud, Exp, Iat, Jti, Scope}` + extra-поля
- `alg.go`: константы `AlgECDSAP256`, `AlgMLDSA44/65/87`, `AlgHybrid*`
- `codec_json.go`: `EncodeJSON` / `DecodeJSON`
- `codec_cbor.go`: CWT-маппинг (`1=sub, 2=iss, 3=aud, 4=exp, 5=iat, 6=jti, 7=scope`)
- `format_text.go`: `base64url(H).base64url(P).base64url(Sig)`
- `format_binary.go`: `uint16 lenH | H | uint16 lenP | P | Sig`
- Тесты: круговая сериализация, edge-cases (пустой scope, длинный sub, юникод)

### Этап 3 — JWK и ротация ключей
- `jwk.go`: типы `JWK`, `JWKSet`
- Расширение `kty: "MLDSA"`
- Поддержка нескольких активных ключей с разными `kid`
- Селектор подписи по `kid` на стороне Issuer
- Селектор верификации по `kid` на стороне Validator
- Тесты: ротация без даунтайма (старый и новый `kid` одновременно)

### Этап 4 — Issuer / Validator + fuzz
- `token.go`: публичный API `Issue(claims, opts) → token`, `Parse(token) → (header, claims, sig)`, `Validate(token, opts) → claims`
- `IssueOptions{Alg, Codec, Format, Signer, Kid}`
- `ValidateOptions{Verifier, ExpectedIss, ExpectedAud, Clock}`
- Валидация claims: `exp`, `nbf`, `iat`, `iss`, `aud`
- Fuzz-тесты `FuzzParseText`, `FuzzParseBinary`
- Тесты: tampering header / payload / signature, истёкший exp, неверный iss/aud

### Этап 5 — Сравнение CBOR-библиотек
- Параметризованный бенч на одном наборе claims: `BenchmarkCBOR_Fxamacker_*`, `BenchmarkCBOR_Ugorji_*`
- Сравнение по размеру вывода и скорости encode/decode
- Цифры — таблица в гл. 4.5

### Этап 6 — CLI-утилита `pqt`
- `cmd/pqt-cli/main.go` на стандартном `flag`
- Команды:
  - `pqt keygen --alg <ecdsa|mldsa44|mldsa65|mldsa87|hybrid> --out keys/`
  - `pqt sign --key <path> --claims <json> [--alg <...>] [--codec <json|cbor>] [--format <text|binary>]`
  - `pqt verify --key <path> --token <path>`
  - `pqt decode --token <path>` — печать header и claims без верификации

### Этап 7 — Сервер авторизации `cmd/pqt-authserver`
- `POST /auth/token`: выдача access + refresh; in-memory store seed-пользователей
- `POST /auth/refresh`: rotation (старый refresh инвалидируется)
- `POST /auth/revoke` (RFC 7009): чёрный список `jti`
- `GET /.well-known/pq-jwks`: публикация всех активных публичных ключей
- `GET /.well-known/oauth-authorization-server` (RFC 8414): метаданные сервера
- `GET /debug/pprof/*`: профилирование (только при `--debug`)
- Конфигурация через env (`PQT_ADDR`, `PQT_ISSUER`, `PQT_KEYS_DIR`)
- E2E-тесты через `httptest`

### Этап 8 — Сервер ресурсов `cmd/pqt-resource`
- Демо-сервер с middleware `RequireValidToken(verifierSet, opts)`
- `GET /me` возвращает claims из контекста
- `GET /admin` требует `scope=admin`
- E2E: интеграция с authserver через `httptest`

### Этап 9 — OpenAPI 3.1
- `api/openapi.yaml` с описанием всех эндпоинтов authserver и resource-server
- Схемы: `TokenRequest`, `TokenResponse`, `JWK`, `JWKSet`, `RevokeRequest`, OAuth metadata
- Подключить статический Swagger UI (этап 10)

### Этап 10 — Web UI + Swagger UI
- `webui/` — формы:
  - выпуск токена (логин/пароль → отображение токена + декода)
  - верификация (вставка токена → результат + содержимое claims)
  - сравнение размеров для разных alg/codec/format на одном наборе claims
- Embed через `//go:embed webui` в authserver
- Swagger UI: маунт `GET /docs/`
- Маршруты `GET /` → главная, `GET /docs/` → Swagger UI

### Этап 11 — Эталонный JWT-сервис
- `cmd/pqt-bench/jwt_baseline.go` (или отдельный пакет `internal/jwtbase`)
- Issuer и Validator на `golang-jwt/jwt/v5` с ES256
- Совместимый набор claims с PQ-AT для прямого сравнения

### Этап 12 — Эксперимент (главы 4.2–4.6)
- 4.2 Производительность ML-DSA: keygen/sign/verify для 44/65/87 → таблица
- 4.3 PQ-AT vs JWT: размеры токенов, latency выпуска и верификации
- 4.4 Эффективность гибрида: последовательная vs параллельная верификация
- 4.5 Эффективность бинарного кодирования: 6 комбинаций (3 alg × 2 codec) × 2 формата + сравнение CBOR-библиотек
- 4.6 Нагрузочное тестирование: vegeta-сценарии, pprof-flamegraph, throughput/latency
- Все результаты собираются в `test/bench/results/*.csv|*.md` для дальнейшей вставки в диссертацию

### Этап 13 — Архитектурный документ
- `docs/architecture.md` — текст-черновик для раздела 3.1 диссертации
- Слои, диаграммы (ASCII / Mermaid), потоки выпуска и верификации

## 5. Дисциплина разработки

- Перед коммитом: `go vet ./...`, `gofmt -l .`, `golangci-lint run ./...` — без замечаний
- Тестовое покрытие критичной логики (формат, подписи, валидация) близко к 100%
- API стандартной библиотеки и сторонних пакетов — сверять с официальной документацией (pkg.go.dev, godoc), не полагаться на устаревшие шпаргалки
- Не использовать `eslint-disable`-аналоги (`//nolint`, `//go:build`-обходы) для подавления реальных проблем — править код
- Обновлять `go.mod` через `go mod tidy` после добавления новой зависимости
- Конфиги `.golangci.yml` / `gofmt` / `tsconfig`-аналогов править только осмысленно, не «чтобы зелёное»
