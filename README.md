# pqt — постквантовый токен доступа

Прототип формата **PQ-AT (Post-Quantum Access Token)** — постквантовая замена JWT с
гибридной схемой подписи (ECDSA P-256 + ML-DSA-65) и компактным CBOR-кодированием.

Реализация главы 3 и экспериментальная база главы 4 магистерской диссертации
**«Построение токена постквантового доступа»** (Тимофеенко С. В., ВГУ ФКН, 2026).

## Стек

- **Go 1.26**
- **`crypto/ecdsa`** — классическая подпись ECDSA P-256
- **`github.com/cloudflare/circl`** — постквантовая ML-DSA (FIPS 204), уровни 44/65/87
- **`github.com/fxamacker/cbor/v2`** — CBOR-кодек (RFC 8949), CWT-стиль (RFC 8392)
- **`github.com/golang-jwt/jwt/v5`** — эталонный JWT для сравнения (глава 4.3)
- **`github.com/tsenart/vegeta/v12`** — нагрузочное тестирование (глава 4.6)
- **`net/http`** — HTTP без сторонних фреймворков
- **`log/slog`** — структурированное логирование

## План работы

Полный план — [docs/plan.md](docs/plan.md). Скоуп зафиксирован: 14 этапов, цикл
«обсуждение → код → тесты → ревью → коммит» на каждом.

## Структура

```
pqt/
├── *.go                    # библиотека формата PQ-AT (плоский корень)
├── cmd/
│   ├── pqt-cli/            # CLI: keygen / sign / verify / decode
│   ├── pqt-authserver/     # сервер авторизации (OAuth 2.0-совместимый)
│   ├── pqt-resource/       # демо-сервер ресурсов с middleware
│   └── pqt-bench/          # сценарии для главы 4
├── api/
│   └── openapi.yaml        # OpenAPI 3.1
├── webui/                  # ассеты для Web UI (embed)
├── docs/                   # документация и черновики для ВКР
└── test/                   # E2E и нагрузочные сценарии
```

## Команды

Все команды запускаются из корня репозитория.

```bash
# Сборка всех бинарников
go build ./...

# Юнит-тесты
go test -count=1 ./...

# Юнит-тесты с детектором гонок
go test -race -count=1 ./...

# Бенчмарки
go test -bench=. -benchmem -run=^$ ./...

# Fuzz-тесты (минута на каждый)
go test -run=^$ -fuzz=. -fuzztime=60s ./...

# Линт
golangci-lint run ./...

# Форматирование
gofmt -s -w .

# Зависимости
go mod tidy

# Запуск сервера авторизации
go run ./cmd/pqt-authserver

# Запуск сервера ресурсов
go run ./cmd/pqt-resource

# CLI
go run ./cmd/pqt-cli help
```

## Установка инструментов

```bash
go install golang.org/x/tools/gopls@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

## Лицензия

Внутренний проект диссертационной работы. Лицензия не определена.
