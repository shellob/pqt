package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"pqt"
	"pqt/token"
)

const decodeUsage = `pqt-cli decode — распечатать содержимое токена без проверки подписи.

Использование:
  pqt-cli decode --token <файл> [--format text|binary]

Опции:
  --token   Путь к файлу с токеном.
  --format  Формат токена: text (по умолчанию) или binary.

Печатается JSON с полями header, claims, signature_size. Подпись не сверяется —
это инструмент для отладки и осмотра. Для безопасной проверки используйте
pqt-cli verify.
`

// decodedView — то, что печатается на stdout: разобранный заголовок,
// разобранные claims и размер подписи в байтах. Сам байтовый блок подписи
// не нужен глазам, поэтому показываем только его длину.
type decodedView struct {
	Header        token.Header `json:"header"`
	Claims        token.Claims `json:"claims"`
	SignatureSize int          `json:"signature_size"`
}

func runDecode(args []string) error {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, decodeUsage) }

	tokenPath := fs.String("token", "", "путь к файлу с токеном")
	formatFlag := fs.String("format", string(token.FormatText), "формат токена (text|binary)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tokenPath == "" {
		fs.Usage()
		return fmt.Errorf("укажите --token")
	}

	tokenFormat := token.Format(*formatFlag)
	tokenBytes, err := readTokenBytes(*tokenPath, tokenFormat)
	if err != nil {
		return err
	}

	header, claims, signature, _, err := pqt.Parse(tokenBytes, tokenFormat)
	if err != nil {
		return fmt.Errorf("разбор токена: %w", err)
	}

	view := decodedView{Header: header, Claims: claims, SignatureSize: len(signature)}

	out, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return fmt.Errorf("сериализация результата: %w", err)
	}
	if _, err := fmt.Fprintln(os.Stdout, string(out)); err != nil {
		return fmt.Errorf("запись в stdout: %w", err)
	}
	return nil
}
