package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pqt"
	"pqt/jwk"
	"pqt/token"
)

// makeClaimsFile сохраняет claims в JSON-файл и возвращает путь к нему.
// Время exp — через час относительно `now`, iat — на `now`.
func makeClaimsFile(t *testing.T, dir string, now time.Time) string {
	t.Helper()
	c := token.Claims{
		Sub:   "user-42",
		Iss:   "https://auth.example.com",
		Aud:   "https://api.example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(time.Hour).Unix(),
		Jti:   "01HXYZ-token-id",
		Scope: "read write",
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal claims: %v", err)
	}
	path := filepath.Join(dir, "claims.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// runE2E прогоняет полный цикл keygen → sign → verify → decode для
// одной комбинации (alg, codec, format).
func runE2E(t *testing.T, alg, codec, format string) {
	t.Helper()

	dir := t.TempDir()
	kid := "test-key"

	if err := runKeygen([]string{"--alg", alg, "--kid", kid, "--out", dir}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	privPath := filepath.Join(dir, kid+".priv.jwk.json")
	pubPath := filepath.Join(dir, kid+".pub.jwk.json")
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("после keygen ожидаем файл %q: %v", p, err)
		}
	}

	now := time.Now()
	claimsPath := makeClaimsFile(t, dir, now)
	tokenPath := filepath.Join(dir, "token.bin")

	if err := runSign([]string{
		"--key", privPath,
		"--claims", claimsPath,
		"--codec", codec,
		"--format", format,
		"--out", tokenPath,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := runVerify([]string{
		"--key", pubPath,
		"--token", tokenPath,
		"--format", format,
		"--issuer", "https://auth.example.com",
		"--audience", "https://api.example.com",
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if err := runDecode([]string{
		"--token", tokenPath,
		"--format", format,
	}); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestE2E_FullMatrix(t *testing.T) {
	algs := []string{
		"ecdsa-p256",
		"mldsa44",
		"mldsa65",
		"mldsa87",
		"hybrid-ecdsa-mldsa65",
	}
	codecs := []string{"json", "cbor"}
	formats := []string{"text", "binary"}

	for _, alg := range algs {
		for _, codec := range codecs {
			for _, format := range formats {
				name := alg + "/" + codec + "/" + format
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					runE2E(t, alg, codec, format)
				})
			}
		}
	}
}

func TestKeygen_RejectsUnknownAlg(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := runKeygen([]string{"--alg", "rsa-pkcs1", "--kid", "k", "--out", dir})
	if err == nil {
		t.Fatal("ожидали ошибку на неизвестный алгоритм")
	}
	if !strings.Contains(err.Error(), "rsa-pkcs1") {
		t.Fatalf("ожидали упоминание неизвестного алгоритма в ошибке, получили %v", err)
	}
}

func TestSubcommands_HelpFlagDoesNotError(t *testing.T) {
	t.Parallel()
	// flag.NewFlagSet с ContinueOnError возвращает flag.ErrHelp при -h.
	// main.go должен это распознать и не печатать «ошибку», но runX-функции
	// саму ошибку всё равно возвращают наверх — проверяем, что это именно
	// flag.ErrHelp, а не маскированный flag.ErrHelp под другой ошибкой.
	cases := []struct {
		name string
		fn   func([]string) error
	}{
		{"keygen", runKeygen},
		{"sign", runSign},
		{"verify", runVerify},
		{"decode", runDecode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.fn([]string{"-h"})
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("ожидали flag.ErrHelp для -h, получили %v", err)
			}
		})
	}
}

func TestKeygen_RequiresFlags(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{},
		{"--alg", "ecdsa-p256"},
		{"--alg", "ecdsa-p256", "--kid", "k"},
	}
	for _, args := range cases {
		if err := runKeygen(args); err == nil {
			t.Fatalf("ожидали ошибку для аргументов %v", args)
		}
	}
}

func TestSign_FailsOnMissingKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	claimsPath := makeClaimsFile(t, dir, time.Now())
	err := runSign([]string{
		"--key", filepath.Join(dir, "nope.json"),
		"--claims", claimsPath,
	})
	if err == nil {
		t.Fatal("ожидали ошибку на отсутствующий ключ")
	}
}

func TestVerify_FailsOnTamperedToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := runKeygen([]string{"--alg", "ecdsa-p256", "--kid", "k", "--out", dir}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now()
	claimsPath := makeClaimsFile(t, dir, now)
	tokenPath := filepath.Join(dir, "token.txt")

	if err := runSign([]string{
		"--key", filepath.Join(dir, "k.priv.jwk.json"),
		"--claims", claimsPath,
		"--out", tokenPath,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Меняем один байт где-то в середине base64-токена — подпись точно
	// не сойдётся (а если задели header/payload — упадёт уже на парсинге).
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("токен пустой")
	}
	mid := len(data) / 2
	if data[mid] == 'A' {
		data[mid] = 'B'
	} else {
		data[mid] = 'A'
	}
	if err := os.WriteFile(tokenPath, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err = runVerify([]string{
		"--key", filepath.Join(dir, "k.pub.jwk.json"),
		"--token", tokenPath,
	})
	if err == nil {
		t.Fatal("ожидали ошибку на модифицированный токен")
	}
}

func TestVerify_FailsOnExpired(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := runKeygen([]string{"--alg", "ecdsa-p256", "--kid", "k", "--out", dir}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Выпускаем токен «из прошлого» — exp на час назад.
	past := time.Now().Add(-2 * time.Hour)
	claimsPath := makeClaimsFile(t, dir, past)
	tokenPath := filepath.Join(dir, "token.txt")

	if err := runSign([]string{
		"--key", filepath.Join(dir, "k.priv.jwk.json"),
		"--claims", claimsPath,
		"--out", tokenPath,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	err := runVerify([]string{
		"--key", filepath.Join(dir, "k.pub.jwk.json"),
		"--token", tokenPath,
	})
	if err == nil {
		t.Fatal("ожидали ErrTokenExpired, получили nil")
	}
	if !errors.Is(err, pqt.ErrTokenExpired) {
		t.Fatalf("ожидали ErrTokenExpired, получили %v", err)
	}
}

func TestDecode_ShowsHeaderAndClaims(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := runKeygen([]string{"--alg", "mldsa65", "--kid", "k", "--out", dir}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	claimsPath := makeClaimsFile(t, dir, time.Now())
	tokenPath := filepath.Join(dir, "token.txt")
	if err := runSign([]string{
		"--key", filepath.Join(dir, "k.priv.jwk.json"),
		"--claims", claimsPath,
		"--codec", "cbor",
		"--out", tokenPath,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := runDecode([]string{"--token", tokenPath}); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Содержимое stdout мы не перехватываем — здесь нам важен сам факт,
	// что decode прошёл без ошибки. Проверка содержимого делается на
	// уровне pqt.Parse (см. issuer_validator_test.go).
}

func TestKeygen_WritesValidJWK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := runKeygen([]string{"--alg", "ecdsa-p256", "--kid", "k", "--out", dir}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	privData, err := os.ReadFile(filepath.Join(dir, "k.priv.jwk.json"))
	if err != nil {
		t.Fatalf("ReadFile priv: %v", err)
	}
	var priv jwk.JWK
	if err := json.Unmarshal(privData, &priv); err != nil {
		t.Fatalf("Unmarshal priv: %v", err)
	}
	if priv.Kid != "k" || priv.Kty != "EC" || priv.Crv != "P-256" {
		t.Fatalf("неожиданный приватный JWK: %+v", priv)
	}

	pubData, err := os.ReadFile(filepath.Join(dir, "k.pub.jwk.json"))
	if err != nil {
		t.Fatalf("ReadFile pub: %v", err)
	}
	if bytes.Contains(pubData, []byte(`"d"`)) {
		t.Fatalf("публичный JWK не должен содержать поле d (приватный материал)")
	}
}
