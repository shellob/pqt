// Package bench — сравнительные бенчмарки для главы 4.3 диссертации:
// PQ-AT vs классический JWT (golang-jwt) на одинаковом наборе claims.
//
// Запуск:
//
//	go test -bench=. -benchmem -run=^$ -benchtime=2s ./internal/bench/...
//
// Дополнительно запускается TestPQATvsJWT_Sizes — печатает реальные
// размеры выпущенных токенов для итоговой таблицы.
package bench_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"pqt"
	"pqt/internal/jwtbase"
	"pqt/keys"
	"pqt/token"
)

// sampleClaims — типовой набор claims для всех сравнений. Совпадает по
// смыслу с тем, что выдаёт authserver: sub, iss, aud, iat, exp, jti, scope.
func sampleClaims() token.Claims {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	return token.Claims{
		Sub:   "user-42",
		Iss:   "https://auth.example.com",
		Aud:   "https://api.example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(time.Hour).Unix(),
		Jti:   "01HXYZ-token-id",
		Scope: "read write",
	}
}

// makeECDSAKey даёт пару ECDSA P-256 в двух представлениях: для нашего
// keys.PrivateKey и для golang-jwt (он принимает *ecdsa.PrivateKey напрямую).
type ecdsaPair struct {
	stdlib *ecdsa.PrivateKey
	pqt    keys.PrivateKey
}

func makeECDSAPair(b testHelper) ecdsaPair {
	b.Helper()

	std, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa generate: %v", err)
	}
	// Восстанавливаем тот же приватный ключ через keys.NewECDSAPrivateFromScalar,
	// чтобы и наш stack, и jwtbase подписывали одним и тем же ключом —
	// и сравнение скоростей шло без перекоса генерации.
	scalarBytes, err := std.Bytes()
	if err != nil {
		b.Fatalf("std bytes: %v", err)
	}
	pqtKey, err := keys.NewECDSAPrivateFromScalar(scalarBytes)
	if err != nil {
		b.Fatalf("pqt key: %v", err)
	}
	return ecdsaPair{stdlib: std, pqt: pqtKey}
}

// testHelper — общий интерфейс между *testing.B и *testing.T, чтобы один
// и тот же makeECDSAPair работал и в бенчмарке, и в обычном тесте размеров.
type testHelper interface {
	Helper()
	Fatalf(format string, args ...any)
}

// --- Issue: PQ-AT (ecdsa-p256) vs JWT (ES256) ---

func BenchmarkIssue_PQAT_ECDSA(b *testing.B) {
	pair := makeECDSAPair(b)
	c := sampleClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pqt.Issue(c, pqt.IssueOptions{
			Signer: pair.pqt,
			Codec:  token.CodecJSON,
			Format: token.FormatText,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIssue_JWT_ES256(b *testing.B) {
	pair := makeECDSAPair(b)
	c := sampleClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := jwtbase.Issue(c, pair.stdlib); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Issue: PQ-AT (mldsa65) vs PQ-AT (hybrid) — для контекста главы 4.3 ---

func BenchmarkIssue_PQAT_MLDSA65(b *testing.B) {
	priv, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
	if err != nil {
		b.Fatal(err)
	}
	c := sampleClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pqt.Issue(c, pqt.IssueOptions{
			Signer: priv,
			Codec:  token.CodecJSON,
			Format: token.FormatText,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIssue_PQAT_Hybrid65(b *testing.B) {
	priv, err := keys.GenerateHybrid(keys.AlgMLDSA65)
	if err != nil {
		b.Fatal(err)
	}
	c := sampleClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pqt.Issue(c, pqt.IssueOptions{
			Signer: priv,
			Codec:  token.CodecJSON,
			Format: token.FormatText,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Validate: PQ-AT (ecdsa-p256) vs JWT (ES256) ---

func BenchmarkValidate_PQAT_ECDSA(b *testing.B) {
	pair := makeECDSAPair(b)
	c := sampleClaims()
	tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
		Signer: pair.pqt,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		b.Fatal(err)
	}
	pub := pair.pqt.Public()
	clock := func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) }
	keySource := func(_ token.Header) (keys.PublicKey, error) { return pub, nil }
	opts := pqt.ValidateOptions{
		KeySource:        keySource,
		Format:           token.FormatText,
		ExpectedIssuer:   c.Iss,
		ExpectedAudience: c.Aud,
		Clock:            clock,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pqt.Validate(tokBytes, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidate_JWT_ES256(b *testing.B) {
	pair := makeECDSAPair(b)
	c := sampleClaims()
	signed, err := jwtbase.Issue(c, pair.stdlib)
	if err != nil {
		b.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) }
	opts := jwtbase.ValidateOptions{
		ExpectedIssuer:   c.Iss,
		ExpectedAudience: c.Aud,
		Clock:            clock,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := jwtbase.Validate(signed, &pair.stdlib.PublicKey, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidate_PQAT_MLDSA65(b *testing.B) {
	priv, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
	if err != nil {
		b.Fatal(err)
	}
	c := sampleClaims()
	tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
		Signer: priv,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.Public()
	clock := func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) }
	opts := pqt.ValidateOptions{
		KeySource:        func(_ token.Header) (keys.PublicKey, error) { return pub, nil },
		Format:           token.FormatText,
		ExpectedIssuer:   c.Iss,
		ExpectedAudience: c.Aud,
		Clock:            clock,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pqt.Validate(tokBytes, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidate_PQAT_Hybrid65(b *testing.B) {
	priv, err := keys.GenerateHybrid(keys.AlgMLDSA65)
	if err != nil {
		b.Fatal(err)
	}
	c := sampleClaims()
	tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
		Signer: priv,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.Public()
	clock := func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) }
	opts := pqt.ValidateOptions{
		KeySource:        func(_ token.Header) (keys.PublicKey, error) { return pub, nil },
		Format:           token.FormatText,
		ExpectedIssuer:   c.Iss,
		ExpectedAudience: c.Aud,
		Clock:            clock,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pqt.Validate(tokBytes, opts); err != nil {
			b.Fatal(err)
		}
	}
}

// TestPQATvsJWT_Sizes печатает реальные размеры выпущенных токенов на одном
// и том же наборе claims. Цифры идут в таблицу главы 4.3 диссертации.
func TestPQATvsJWT_Sizes(t *testing.T) {
	pair := makeECDSAPair(t)
	c := sampleClaims()

	type row struct {
		name  string
		bytes int
	}
	rows := []row{}

	// JWT (ES256, эталон).
	if signed, err := jwtbase.Issue(c, pair.stdlib); err != nil {
		t.Fatalf("jwt: %v", err)
	} else {
		rows = append(rows, row{"JWT (ES256)", len(signed)})
	}

	// PQ-AT в трёх режимах: только ECDSA, только ML-DSA-65, гибрид.
	// Codec=json, Format=text — самый совместимый с JWT режим.
	cases := []struct {
		name    string
		makeKey func() (keys.PrivateKey, error)
	}{
		{"PQ-AT ecdsa-p256 (json/text)", func() (keys.PrivateKey, error) { return pair.pqt, nil }},
		{"PQ-AT mldsa65 (json/text)", func() (keys.PrivateKey, error) {
			return keys.GenerateMLDSA(keys.AlgMLDSA65)
		}},
		{"PQ-AT hybrid-mldsa65 (json/text)", func() (keys.PrivateKey, error) {
			return keys.GenerateHybrid(keys.AlgMLDSA65)
		}},
	}
	for _, tc := range cases {
		signer, err := tc.makeKey()
		if err != nil {
			t.Fatalf("%s key: %v", tc.name, err)
		}
		tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
			Signer: signer,
			Codec:  token.CodecJSON,
			Format: token.FormatText,
		})
		if err != nil {
			t.Fatalf("%s issue: %v", tc.name, err)
		}
		rows = append(rows, row{tc.name, len(tokBytes)})
	}

	// Дополнительно: PQ-AT mldsa65 в бинарном CBOR — это компактнейший
	// режим, нужен для контекста (см. главу 4.5).
	mlPriv, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
	if err != nil {
		t.Fatalf("mldsa key: %v", err)
	}
	tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
		Signer: mlPriv,
		Codec:  token.CodecCBOR,
		Format: token.FormatBinary,
	})
	if err != nil {
		t.Fatalf("mldsa cbor binary: %v", err)
	}
	rows = append(rows, row{"PQ-AT mldsa65 (cbor/binary)", len(tokBytes)})

	t.Log("\nРазмеры выпущенных токенов на одном и том же наборе claims:")
	t.Logf("  %-40s %s", "Формат", "Байт")
	for _, r := range rows {
		t.Logf("  %-40s %d", r.name, r.bytes)
	}
}
