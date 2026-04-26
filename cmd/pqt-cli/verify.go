package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"pqt"
	"pqt/jwk"
	"pqt/keys"
	"pqt/token"
)

const verifyUsage = `pqt-cli verify — проверить токен публичным ключом.

Использование:
  pqt-cli verify --key <pub.jwk.json> --token <файл>
                 [--format text|binary]
                 [--issuer <iss>] [--audience <aud>] [--leeway <duration>]

Опции:
  --key       Путь к публичному ключу в JWK-формате.
  --token     Путь к файлу с токеном.
  --format    Формат токена: text (по умолчанию) или binary.
  --issuer    Если задан, поле iss в токене должно совпасть с этим значением.
  --audience  Если задан, поле aud в токене должно совпасть с этим значением.
  --leeway    Допустимая разница часов с issuer'ом (например, 1m или 30s).
              По умолчанию 0.

Код возврата 0 — токен валиден; 1 — что-то не так. Описание ошибки идёт в stderr.
`

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, verifyUsage) }

	keyPath := fs.String("key", "", "путь к публичному ключу")
	tokenPath := fs.String("token", "", "путь к файлу с токеном")
	formatFlag := fs.String("format", string(token.FormatText), "формат токена (text|binary)")
	issuer := fs.String("issuer", "", "ожидаемое значение claim iss")
	audience := fs.String("audience", "", "ожидаемое значение claim aud")
	leeway := fs.Duration("leeway", 0, "допуск рассинхронизации часов")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *tokenPath == "" {
		fs.Usage()
		return fmt.Errorf("укажите --key и --token")
	}

	keyJWK, err := readJWK(*keyPath)
	if err != nil {
		return err
	}
	verifier, err := jwk.ParsePublic(keyJWK)
	if err != nil {
		return fmt.Errorf("разбор публичного ключа: %w", err)
	}

	tokenFormat := token.Format(*formatFlag)
	tokenBytes, err := readTokenBytes(*tokenPath, tokenFormat)
	if err != nil {
		return err
	}

	claims, err := pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource:        staticVerifier(verifier),
		Format:           tokenFormat,
		ExpectedIssuer:   *issuer,
		ExpectedAudience: *audience,
		Leeway:           *leeway,
		Clock:            time.Now,
	})
	if err != nil {
		return err
	}

	printVerifyResult(claims)
	return nil
}

// staticVerifier — простейший KeySource: всегда возвращает один и тот же
// публичный ключ, без поиска по kid. CLI верифицирует одним конкретным
// ключом, так что выбор не нужен.
func staticVerifier(pub keys.PublicKey) pqt.KeySource {
	return func(token.Header) (keys.PublicKey, error) {
		return pub, nil
	}
}

func printVerifyResult(c token.Claims) {
	// Ошибки печати в stdout игнорируем сознательно: если pipe закрылся
	// (например, пользователь нажал q в pager'е), писать всё равно некуда,
	// а возвращать ошибку из «успешного» verify было бы неожиданно для CLI.
	_, _ = fmt.Fprintln(os.Stdout, "OK")
	_, _ = fmt.Fprintf(os.Stdout, "  sub:   %s\n", c.Sub)
	_, _ = fmt.Fprintf(os.Stdout, "  iss:   %s\n", c.Iss)
	_, _ = fmt.Fprintf(os.Stdout, "  aud:   %s\n", c.Aud)
	_, _ = fmt.Fprintf(os.Stdout, "  exp:   %d\n", c.Exp)
	_, _ = fmt.Fprintf(os.Stdout, "  iat:   %d\n", c.Iat)
	_, _ = fmt.Fprintf(os.Stdout, "  jti:   %s\n", c.Jti)
	_, _ = fmt.Fprintf(os.Stdout, "  scope: %s\n", c.Scope)
}
