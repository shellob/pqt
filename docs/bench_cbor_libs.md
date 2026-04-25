# Сравнение CBOR-библиотек (этап 5, глава 4.5)

Замеры выполнены на одном наборе claims (`token.Claims` с заполненными
sub/iss/aud/iat/exp/jti/scope) на машине AMD Ryzen 7 9800X3D (Windows, Go).

Команда замера: `go test -bench=BenchmarkCBOR -benchmem -run=^$ -benchtime=2s ./token/...`
Размеры: `go test -v -run TestCBORLibsOutputSize ./token/...`

Обе библиотеки используются в той же конфигурации, что и production-код
PQ-AT (см. `token/codec_payload.go`):
- fxamacker — `CanonicalEncOptions().EncMode()` для encode и `DupMapKey:
  DupMapKeyEnforcedAPF` для decode (handle создаётся один раз);
- ugorji — `CborHandle{Canonical: true}` (handle создаётся один раз).

## Размер вывода

| Сценарий              | Библиотека                | Байт |
|-----------------------|---------------------------|-----:|
| Claims (типизованная) | fxamacker (cbor:keyasint) |  103 |
| Claims (типизованная) | ugorji (json fallback)    |  126 |
| `map[int]any`         | fxamacker                 |  103 |
| `map[int]any`         | ugorji                    |  103 |

Уточнение по ugorji: библиотека читает теги в порядке `codec` → `json` →
имя поля. У `token.Claims` тега `codec` нет, есть `json` — ugorji берёт
строковые имена «sub», «iss» и т. д. Это +22% к размеру для типового
набора claims по сравнению с CWT-стилем fxamacker. Если бы у Claims был
тег `codec:"1,..."`, ugorji дал бы аналогичные 103 байта — но это уже
не «из коробки», а ручная подгонка под формат.

На «голом» `map[int]any` обе библиотеки дают идентичный байтовый вывод
(подтверждается тестом `TestCBORLibsAgreeOnMapInt`).

## Скорость

| Бенчмарк                         | ns/op  | B/op | allocs/op |
|----------------------------------|-------:|-----:|----------:|
| Encode/fxamacker/Claims          |   150  |  112 |         1 |
| Encode/ugorji/Claims             |   435  |  824 |         7 |
| Decode/fxamacker/Claims          |   344  |  184 |         6 |
| Decode/ugorji/Claims             |   347  |  824 |         7 |
| Encode/fxamacker/`map[int]any`   |   507  |  160 |         2 |
| Encode/ugorji/`map[int]any`      |   360  |  608 |         6 |
| Decode/fxamacker/`map[int]any`   |   899  |  472 |        17 |
| Decode/ugorji/`map[int]any`      |   768  | 1104 |        17 |

## Выводы для PQ-AT

1. На типизованной `Claims`, которая используется в production-коде,
   **fxamacker** обгоняет ugorji в 2.9 раза по encode и идёт паритетом
   по decode, при этом потребляет в 7 раз меньше памяти на encode
   (112 B/op против 824 B/op).
2. На сыром `map[int]any` ugorji обгоняет fxamacker в 1.4 раза на encode
   и в 1.2 раза на decode. Это контрольный сценарий: он нужен, чтобы
   изолировать стратегию разметки (теги) от чистой скорости кодека —
   когда разметки нет, обе либы работают на одинаковых байтах.
   В production PQ-AT этот путь не используется: токен всегда собирается
   из типизованной `Claims`. Замечание: декод в `map[int]any` приводит
   значения к разным конкретным типам внутри `any` в зависимости от либы
   (например, числа могут стать `int64` или `uint64`), но размер вывода
   при кодировании совпадает.
3. Главное преимущество fxamacker — поддержка тега `cbor:"<n>,keyasint"`,
   которая «бесплатно» даёт CWT-совместимый вывод и -22% к размеру токена.

Выбор `github.com/fxamacker/cbor/v2` в плане проекта (см. `docs/plan.md`,
раздел 1) подтверждается экспериментально.
