// Команда pqt-cli — утилита командной строки для всего, что связано с
// токенами PQ-AT: создать ключ, выпустить токен, проверить подпись,
// посмотреть содержимое. Этот же бинарник используется в тестах из
// internal/bench/* для подготовки токенов и ключей.
//
// Реализованы четыре подкоманды:
//
//   - keygen — сгенерировать пару (приватный + публичный) ключей и сохранить
//     их в два отдельных JWK-файла. Сразу же выбирается алгоритм
//     (ECDSA P-256, ML-DSA-44/65/87 или гибрид).
//   - sign   — взять claims из JSON-файла, подписать их приватным ключом
//     и вывести готовый токен в текстовом или бинарном формате.
//   - verify — проверить подпись токена публичным ключом, проверить exp
//     и при желании issuer/audience. При успехе печатает claims.
//   - decode — распечатать заголовок и claims без проверки подписи.
//     Полезно при отладке: подпись могла не сойтись из-за неправильного
//     ключа, но содержимое токена увидеть всё равно надо.
//
// Краткая помощь по конкретной подкоманде — `pqt-cli <cmd> -h`.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const usage = `pqt-cli — утилита для работы с постквантовыми токенами PQ-AT.

Использование:
  pqt-cli <команда> [опции]

Команды:
  keygen   сгенерировать пару ключей в JWK-формате
  sign     выпустить подписанный токен
  verify   проверить токен публичным ключом
  decode   распечатать содержимое токена без проверки

Подсказка по конкретной команде: pqt-cli <команда> -h.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "keygen":
		err = runKeygen(args)
	case "sign":
		err = runSign(args)
	case "verify":
		err = runVerify(args)
	case "decode":
		err = runDecode(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "pqt-cli: неизвестная команда %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		// При -h/--help пакет flag намеренно возвращает специальную ошибку
		// flag.ErrHelp. Сама справка уже напечатана внутри FlagSet.Parse
		// через Usage, и если бы мы здесь добавляли ещё «error: flag: help
		// requested» и завершались кодом 1, пользователь видел бы лишнюю
		// строчку об ошибке после совершенно нормальной справки. Поэтому
		// для ErrHelp выходим спокойно с кодом 0.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "pqt-cli %s: %v\n", cmd, err)
		os.Exit(1)
	}
}
