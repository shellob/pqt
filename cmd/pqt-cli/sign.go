package main

import (
	"flag"
	"fmt"
	"os"

	"pqt"
	"pqt/jwk"
	"pqt/token"
)

const signUsage = `pqt-cli sign — выпустить подписанный токен PQ-AT.

Использование:
  pqt-cli sign --key <priv.jwk.json> --claims <claims.json>
               [--codec json|cbor] [--format text|binary] [--out <файл>]

Опции:
  --key     Путь к приватному ключу в JWK-формате (см. pqt-cli keygen).
  --claims  Путь к JSON-файлу с claims. Поля: sub, iss, aud, exp, iat, jti, scope.
            exp/iat — целочисленный Unix timestamp в секундах.
  --codec   Кодек payload: json или cbor. По умолчанию json.
  --format  Формат токена: text (JWT-совместимый) или binary. По умолчанию text.
  --out     Куда записать токен. Если не указано — пишется в stdout.
`

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, signUsage) }

	keyPath := fs.String("key", "", "путь к приватному ключу")
	claimsPath := fs.String("claims", "", "путь к claims JSON")
	codec := fs.String("codec", string(token.CodecJSON), "кодек payload (json|cbor)")
	format := fs.String("format", string(token.FormatText), "формат токена (text|binary)")
	outPath := fs.String("out", "", "куда записать токен (по умолчанию stdout)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *claimsPath == "" {
		fs.Usage()
		return fmt.Errorf("укажите --key и --claims")
	}

	keyJWK, err := readJWK(*keyPath)
	if err != nil {
		return err
	}
	signer, err := jwk.ParsePrivate(keyJWK)
	if err != nil {
		return fmt.Errorf("разбор приватного ключа: %w", err)
	}

	claims, err := readClaims(*claimsPath)
	if err != nil {
		return err
	}

	tokenBytes, err := pqt.Issue(claims, pqt.IssueOptions{
		Signer: signer,
		Codec:  token.Codec(*codec),
		Format: token.Format(*format),
		Kid:    keyJWK.Kid,
	})
	if err != nil {
		return fmt.Errorf("выпуск токена: %w", err)
	}

	return writeBytes(*outPath, tokenBytes, token.Format(*format), os.Stdout)
}
