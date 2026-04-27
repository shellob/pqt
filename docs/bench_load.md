# Нагрузочное тестирование (этап 12в, глава 4.6)

В отличие от глав 4.2–4.5, где замеры делались `go test -bench` на уровне
функций, для главы 4.6 нагрузка идёт на полный путь HTTP-запроса:
TCP-connect → http-парсинг → middleware → выпуск/проверка токена →
сериализация ответа. Это включает и накладные расходы стека Go и сети.

Используется библиотека и CLI [vegeta v12](https://github.com/tsenart/vegeta)
из плана проекта.

## Что грузим

Два сценария отражают двух хозяев нагрузки в реальной системе:

- **`token`** — POST /auth/token. Выпуск access + refresh пары. Hot-path
  включает bcrypt-сравнение пароля, генерацию jti, подпись H||P. Это
  «дорогой» запрос: bcrypt cost=10 даёт ~1 мс per call даже без подписи.
- **`me`** — GET /me на resource-сервере. Проверка Bearer-токена через
  JWKSClient + pqt.Validate. Это «дешёвый» запрос: всё определяется
  скоростью verify подписи и парсинга формата.

## Запуск

В двух разных терминалах поднимаем серверы (с включенным pprof для главы):

```bash
# Терминал 1: auth-сервер
PQT_GENERATE_ALG=hybrid-ecdsa-mldsa65 \
  go run ./cmd/pqt-authserver --debug

# Терминал 2: resource-сервер (только для сценария me)
PQT_AUTH_BASE_URL=http://localhost:8080 \
PQT_RESOURCE_ISSUER=http://localhost:8080 \
PQT_RESOURCE_AUDIENCE=http://localhost:8080 \
  go run ./cmd/pqt-resource
```

В третьем терминале — нагрузка:

```bash
# Сценарий token: 100 RPS × 30s
go run ./cmd/pqt-loadtest --scenario token --rate 100 --duration 30s

# Сценарий me
go run ./cmd/pqt-loadtest --scenario me --rate 500 --duration 30s
```

Параллельно — снимаем профиль (одну из команд, на разные интересующие
компоненты):

```bash
go tool pprof -http=:6060 http://localhost:8080/debug/pprof/profile?seconds=30
go tool pprof -http=:6060 http://localhost:8080/debug/pprof/heap
go tool pprof -http=:6060 http://localhost:8080/debug/pprof/goroutine
```

## Шаблон таблиц для главы 4.6

После каждого прогона vegeta печатает текстовый отчёт примерно вида:

```
Requests      [total, rate, throughput]  3000, 100.03, 99.98
Duration      [total, attack, wait]      30.005s, 29.991s, 14.215ms
Latencies     [min, mean, 50, 90, 95, 99, max] ...
Bytes In      [total, mean]              1234567, 411.52
Bytes Out     [total, mean]              ...
Success       [ratio]                    100.00%
Status Codes  [code:count]               200:3000
```

Цифры из отчёта собираются в две таблицы — одна на /auth/token, другая
на /me. Шаблон:

| Алгоритм       | Rate (RPS) | p50 | p95 | p99 | Success |
|----------------|-----------:|----:|----:|----:|--------:|
| ecdsa-p256     |          ? |   ? |   ? |   ? |       ? |
| mldsa65        |          ? |   ? |   ? |   ? |       ? |
| hybrid-mldsa65 |          ? |   ? |   ? |   ? |       ? |

Прогон делается отдельно для каждого алгоритма: перезапуск auth-сервера
с разным `PQT_GENERATE_ALG`, потом снова нагрузка.

## Поведение под пределом

Помимо линейной нагрузки на фиксированном RPS, в диссертацию идут два
разворота:

- **«rate ramp»** — постепенно увеличиваем RPS до точки, где p99 latency
  превышает 1 секунду или success ratio падает ниже 99%. Это и есть
  максимальная пропускная способность при заданном алгоритме.
- **«burst»** — вкладываем в одну секунду 10× от стационарной нагрузки.
  Замеряем, как восстанавливается p99 после всплеска.

Vegeta поддерживает оба сценария через свои `Pacer`-ы (см. опции `vegeta attack`
напрямую или собственная команда с custom rate). Для прототипа диплома
достаточно фиксированного RPS — оба разворота можно сделать вручную через
несколько прогонов с разными `--rate`.

## Smoke-тест в репо

Файл [`internal/bench/load_smoke_test.go`](../internal/bench/load_smoke_test.go)
поднимает auth-сервер через `httptest.NewServer` и гоняет vegeta 50 RPS × 1
секунда. Цель не научный замер, а проверка что:

- сценарий нагрузки собирается и работает;
- сервер не теряет запросы при минимальной параллельной нагрузке.

Запуск:

```bash
go test -count=1 -v -run=TestLoadSmoke ./internal/bench/...
```

## Известное ограничение этих замеров

bcrypt cost задаётся через `PQT_BCRYPT_COST`. По умолчанию = 10 (production-
безопасный). При нагрузке на /auth/token bcrypt становится главным
узким местом — даже на 16-ядерном CPU стабильный throughput ограничен
~600–800 RPS просто из-за времени хеширования. Это не баг, а свойство
выбранного алгоритма; для сравнения скорости подписей в чистом виде
лучше использовать главу 4.3 (`internal/bench/pqat_vs_jwt_bench_test.go`).
