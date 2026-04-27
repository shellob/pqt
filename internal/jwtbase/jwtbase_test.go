package jwtbase_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"pqt/internal/jwtbase"
	"pqt/token"
)

// fixedClock возвращает Clock, который всегда отдаёт одно и то же время —
// удобно проверять exp на конкретной границе.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// makeKey генерирует свежую пару ECDSA P-256 для тестов.
func makeKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// sampleClaims — стандартный набор claims для тестов. Время exp — через
// час после `now`. Кладём ровно те же поля, которыми оперирует pqt, чтобы
// на стороне эксперимента можно было сравнивать одинаковые токены.
func sampleClaims(now time.Time) token.Claims {
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

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)
	want := sampleClaims(now)

	signed, err := jwtbase.Issue(want, key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if strings.Count(signed, ".") != 2 {
		t.Fatalf("ожидали 2 точки в JWT, получили %q", signed)
	}

	got, err := jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		ExpectedIssuer:   want.Iss,
		ExpectedAudience: want.Aud,
		Clock:            fixedClock(now),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip изменил claims:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestIssue_DropsKindField(t *testing.T) {
	t.Parallel()

	key := makeKey(t)
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	in := sampleClaims(now)
	in.Kind = token.KindAccess

	signed, err := jwtbase.Issue(in, key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		Clock: fixedClock(now),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Kind != "" {
		t.Fatalf("Kind просочился в JWT: %q (должен пропадать при выпуске)", got.Kind)
	}
}

func TestValidate_TamperedToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)

	signed, err := jwtbase.Issue(sampleClaims(now), key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Подменяем один символ в середине токена.
	bs := []byte(signed)
	mid := len(bs) / 2
	if bs[mid] == 'a' {
		bs[mid] = 'b'
	} else {
		bs[mid] = 'a'
	}

	_, err = jwtbase.Validate(string(bs), &key.PublicKey, jwtbase.ValidateOptions{
		Clock: fixedClock(now),
	})
	if err == nil {
		t.Fatal("ожидали ошибку на подменённом токене")
	}
}

func TestValidate_WrongPublicKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer := makeKey(t)
	other := makeKey(t)

	signed, err := jwtbase.Issue(sampleClaims(now), signer)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = jwtbase.Validate(signed, &other.PublicKey, jwtbase.ValidateOptions{
		Clock: fixedClock(now),
	})
	if !errors.Is(err, jwtbase.ErrSignatureInvalid) {
		t.Fatalf("ожидали ErrSignatureInvalid, получили %v", err)
	}
}

func TestValidate_Expired(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)

	signed, err := jwtbase.Issue(sampleClaims(issued), key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Сдвигаем «сейчас» на два часа после выпуска — exp точно в прошлом.
	later := issued.Add(2 * time.Hour)

	_, err = jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		Clock: fixedClock(later),
	})
	if !errors.Is(err, jwtbase.ErrTokenExpired) {
		t.Fatalf("ожидали ErrTokenExpired, получили %v", err)
	}
}

func TestValidate_LeewayLetsExpiredThrough(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)

	signed, err := jwtbase.Issue(sampleClaims(issued), key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	thirtySecondsLater := issued.Add(time.Hour + 30*time.Second)
	_, err = jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		Clock:  fixedClock(thirtySecondsLater),
		Leeway: time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate с Leeway: %v", err)
	}
}

func TestValidate_IssuerMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)

	signed, err := jwtbase.Issue(sampleClaims(now), key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		ExpectedIssuer: "https://other.example.com",
		Clock:          fixedClock(now),
	})
	if !errors.Is(err, jwtbase.ErrIssuerMismatch) {
		t.Fatalf("ожидали ErrIssuerMismatch, получили %v", err)
	}
}

func TestValidate_AudienceMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)

	signed, err := jwtbase.Issue(sampleClaims(now), key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		ExpectedAudience: "https://other.example.com",
		Clock:            fixedClock(now),
	})
	if !errors.Is(err, jwtbase.ErrAudienceMismatch) {
		t.Fatalf("ожидали ErrAudienceMismatch, получили %v", err)
	}
}

func TestValidate_AudienceMatchInMultiAudienceToken(t *testing.T) {
	t.Parallel()

	// JWT с массивом aud ["api1", "api2"] — RFC 7519 §4.1.3 разрешает aud
	// быть массивом, валидно если хотя бы один совпадает с ожидаемым.
	// Прямо через jwtbase.Issue выпустить такой токен нельзя (наш token.Claims
	// хранит один aud), поэтому собираем токен напрямую.
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	key := makeKey(t)

	type multiAudClaims struct {
		Scope string `json:"scope,omitempty"`
		jwt.RegisteredClaims
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, multiAudClaims{
		Scope: "read",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "https://auth.example.com",
			Audience:  jwt.ClaimStrings{"api1", "api2"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	// ExpectedAudience = "api2" — он не первый, но в массиве он есть.
	got, err := jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		ExpectedAudience: "api2",
		Clock:            fixedClock(now),
	})
	if err != nil {
		t.Fatalf("Validate: %v (mismatch на aud[1] — баг в проверке)", err)
	}
	if got.Sub != "user-1" {
		t.Fatalf("sub = %q", got.Sub)
	}

	// А вот api3 в массиве нет — должна быть ошибка.
	_, err = jwtbase.Validate(signed, &key.PublicKey, jwtbase.ValidateOptions{
		ExpectedAudience: "api3",
		Clock:            fixedClock(now),
	})
	if !errors.Is(err, jwtbase.ErrAudienceMismatch) {
		t.Fatalf("ожидали ErrAudienceMismatch для api3, получили %v", err)
	}
}

func TestIssue_NilKey(t *testing.T) {
	t.Parallel()
	if _, err := jwtbase.Issue(token.Claims{}, nil); err == nil {
		t.Fatal("ожидали ошибку на nil key")
	}
}

func TestValidate_NilKey(t *testing.T) {
	t.Parallel()
	if _, err := jwtbase.Validate("anything", nil, jwtbase.ValidateOptions{}); err == nil {
		t.Fatal("ожидали ошибку на nil key")
	}
}

// TestSize_BaselineApproximate проверяет, что размер выпущенного JWT с
// типовым набором claims укладывается в ожидаемый диапазон 300–400 байт
// (ВКР, раздел 2.4: «классический JWT с подписью ES256 — 300–400 байт»).
// Это не строгий контракт: точное число байт зависит от длины полей.
// Назначение теста — поймать регресс, если кто-то перейдёт на HS256 или
// другой алгоритм с заметно иной длиной подписи.
func TestSize_BaselineApproximate(t *testing.T) {
	t.Parallel()

	key := makeKey(t)
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signed, err := jwtbase.Issue(sampleClaims(now), key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	size := len(signed)
	if size < 250 || size > 500 {
		t.Fatalf("неожиданный размер JWT: %d байт (ожидали 250..500)", size)
	}
	t.Logf("эталонный JWT (ES256, типовые claims) — %d байт", size)
}
