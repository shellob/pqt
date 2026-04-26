// Команда pqt-cli — утилита для работы с токенами PQ-AT из командной строки.
//
// Поддерживаются четыре подкоманды:
//
//   - keygen — сгенерировать пару ключей и положить её в JWK-файлы;
//   - sign   — выпустить подписанный токен по claims из JSON-файла;
//   - verify — проверить токен публичным ключом;
//   - decode — распечатать header и claims токена без проверки подписи.
//
// Полная справка по каждой команде доступна через `pqt-cli <cmd> -h`.
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
		// flag.ErrHelp возвращается при -h/--help у подкоманды. flag.NewFlagSet
		// уже сам напечатал справку через свой Usage; печатать «error: flag:
		// help requested» и завершаться с кодом 1 — плохой UX.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "pqt-cli %s: %v\n", cmd, err)
		os.Exit(1)
	}
}
