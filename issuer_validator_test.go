package pqt_test

import (
	"errors"
	"testing"
	"time"

	"pqt"
	"pqt/keys"
	"pqt/token"
)

// fixedClock возвращает Clock, который всегда отдаёт одно и то же время —
// удобно проверять exp на конкретной границе.
func fixedClock(t time.Time) pqt.Clock {
	return func() time.Time { return t }
}

// staticKey — простейший KeySource: всегда отдаёт один и тот же публичный
// ключ. В реальной жизни вместо него обычно поиск в jwk.Set по kid.
func staticKey(pub keys.PublicKey) pqt.KeySource {
	return func(_ token.Header) (keys.PublicKey, error) {
		return pub, nil
	}
}

// Стандартный набор claims для тестов: токен валиден часовой зоной вокруг
// 2026-04-25.
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

// algMatrix описывает все поддерживаемые сочетания alg + kind для round-trip.
type algCase struct {
	name    string
	makeKey func(t *testing.T) keys.PrivateKey
}

func algMatrix() []algCase {
	return []algCase{
		{
			name: "ecdsa-p256",
			makeKey: func(t *testing.T) keys.PrivateKey {
				t.Helper()
				k, err := keys.GenerateECDSA()
				if err != nil {
					t.Fatalf("GenerateECDSA: %v", err)
				}
				return k
			},
		},
		{
			name: "mldsa44",
			makeKey: func(t *testing.T) keys.PrivateKey {
				t.Helper()
				k, err := keys.GenerateMLDSA(keys.AlgMLDSA44)
				if err != nil {
					t.Fatalf("GenerateMLDSA(44): %v", err)
				}
				return k
			},
		},
		{
			name: "mldsa65",
			makeKey: func(t *testing.T) keys.PrivateKey {
				t.Helper()
				k, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
				if err != nil {
					t.Fatalf("GenerateMLDSA(65): %v", err)
				}
				return k
			},
		},
		{
			name: "mldsa87",
			makeKey: func(t *testing.T) keys.PrivateKey {
				t.Helper()
				k, err := keys.GenerateMLDSA(keys.AlgMLDSA87)
				if err != nil {
					t.Fatalf("GenerateMLDSA(87): %v", err)
				}
				return k
			},
		},
		{
			name: "hybrid-ecdsa-mldsa65",
			makeKey: func(t *testing.T) keys.PrivateKey {
				t.Helper()
				k, err := keys.GenerateHybrid(keys.AlgMLDSA65)
				if err != nil {
					t.Fatalf("GenerateHybrid(65): %v", err)
				}
				return k
			},
		},
	}
}

func TestIssueValidate_RoundTripFullMatrix(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	codecs := []token.Codec{token.CodecJSON, token.CodecCBOR}
	formats := []token.Format{token.FormatText, token.FormatBinary}

	for _, ac := range algMatrix() {
		for _, codec := range codecs {
			for _, format := range formats {
				t.Run(ac.name+"/"+string(codec)+"/"+string(format), func(t *testing.T) {
					t.Parallel()

					signer := ac.makeKey(t)
					claims := sampleClaims(now)

					tokenBytes, err := pqt.Issue(claims, pqt.IssueOptions{
						Signer: signer,
						Codec:  codec,
						Format: format,
						Kid:    "k-1",
					})
					if err != nil {
						t.Fatalf("Issue: %v", err)
					}
					if len(tokenBytes) == 0 {
						t.Fatal("Issue вернул пустые байты")
					}

					got, err := pqt.Validate(tokenBytes, pqt.ValidateOptions{
						KeySource:        staticKey(signer.Public()),
						Format:           format,
						ExpectedIssuer:   claims.Iss,
						ExpectedAudience: claims.Aud,
						Clock:            fixedClock(now),
					})
					if err != nil {
						t.Fatalf("Validate: %v", err)
					}
					if got != claims {
						t.Fatalf("round-trip изменил claims:\n got=%+v\nwant=%+v", got, claims)
					}
				})
			}
		}
	}
}

func TestValidate_TamperedHeader(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatBinary,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Меняем первый байт сериализованного заголовка — сразу после
	// двухбайтового префикса длины бинарного формата.
	const binaryLengthPrefixSize = 2
	tokenBytes[binaryLengthPrefixSize] ^= 0xff

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatBinary,
		Clock:     fixedClock(now),
	})
	if err == nil {
		t.Fatal("ожидали ошибку при подмене заголовка")
	}
}

func TestValidate_TamperedPayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatBinary,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Меняем байт в середине буфера — там почти наверняка лежит payload
	// (header ~60 байт, потом 2 байта длины payload, сам payload ~150 байт,
	// в конце ASN.1-DER подпись ECDSA ~70 байт).
	target := len(tokenBytes) / 2
	tokenBytes[target] ^= 0x01

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatBinary,
		Clock:     fixedClock(now),
	})
	if err == nil {
		t.Fatal("ожидали ошибку при подмене payload, получили nil")
	}
	// Подмена внутри payload даёт либо ErrSignatureInvalid (verify не сошёлся),
	// либо token.ErrMalformed (если задели длину/структуру JSON).
	if !errors.Is(err, pqt.ErrSignatureInvalid) && !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrSignatureInvalid или token.ErrMalformed, получили %v", err)
	}
}

func TestValidate_TamperedSignature(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatBinary,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Подпись лежит в самом конце бинарного формата.
	tokenBytes[len(tokenBytes)-1] ^= 0xff

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatBinary,
		Clock:     fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrSignatureInvalid) {
		t.Fatalf("ожидали ErrSignatureInvalid, получили %v", err)
	}
}

func TestValidate_Expired(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(issued), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Сдвигаем «сейчас» на два часа после выпуска — exp точно в прошлом
	// (выпустили на 1 час).
	later := issued.Add(2 * time.Hour)

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatText,
		Clock:     fixedClock(later),
	})
	if !errors.Is(err, pqt.ErrTokenExpired) {
		t.Fatalf("ожидали ErrTokenExpired, получили %v", err)
	}
}

func TestValidate_RejectsZeroExp(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	// По спецификации PQ-AT exp обязательное; токен без exp = «вечный
	// access» — validator обязан отвергать.
	claims := sampleClaims(now)
	claims.Exp = 0

	tokenBytes, err := pqt.Issue(claims, pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatText,
		Clock:     fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrTokenExpired) {
		t.Fatalf("ожидали ErrTokenExpired для exp=0, получили %v", err)
	}
}

func TestValidate_LeewayLetsExpiredThrough(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(issued), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Часы клиента ушли на 30 секунд за exp; Leeway 60 секунд должна это
	// проглотить.
	thirtySecondsLater := issued.Add(time.Hour + 30*time.Second)

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatText,
		Clock:     fixedClock(thirtySecondsLater),
		Leeway:    time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate с Leeway: %v", err)
	}
}

func TestValidate_IssuerMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource:      staticKey(signer.Public()),
		Format:         token.FormatText,
		ExpectedIssuer: "https://other.example.com",
		Clock:          fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrIssuerMismatch) {
		t.Fatalf("ожидали ErrIssuerMismatch, получили %v", err)
	}
}

func TestValidate_AudienceMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource:        staticKey(signer.Public()),
		Format:           token.FormatText,
		ExpectedAudience: "https://other.example.com",
		Clock:            fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrAudienceMismatch) {
		t.Fatalf("ожидали ErrAudienceMismatch, получили %v", err)
	}
}

func TestValidate_AlgConfusionAttack(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	// Issuer выпустил токен ECDSA-ключом.
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}
	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// А KeySource ошибочно (или злонамеренно) возвращает ML-DSA-ключ —
	// другой алгоритм. Validator обязан это поймать ДО verify, иначе
	// возможна alg-confusion атака.
	otherSigner, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSA: %v", err)
	}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(otherSigner.Public()),
		Format:    token.FormatText,
		Clock:     fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrAlgMismatch) {
		t.Fatalf("ожидали ErrAlgMismatch, получили %v", err)
	}
}

func TestValidate_KeySourceReturnsError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: func(_ token.Header) (keys.PublicKey, error) {
			return nil, pqt.ErrKeyNotFound
		},
		Format: token.FormatText,
		Clock:  fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrKeyNotFound) {
		t.Fatalf("ожидали ErrKeyNotFound, получили %v", err)
	}
}

func TestValidate_KeySourceReturnsNil(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: func(_ token.Header) (keys.PublicKey, error) {
			return nil, nil
		},
		Format: token.FormatText,
		Clock:  fixedClock(now),
	})
	if !errors.Is(err, pqt.ErrKeyNotFound) {
		t.Fatalf("ожидали ErrKeyNotFound, получили %v", err)
	}
}

func TestIssue_RejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	cases := []struct {
		name string
		opts pqt.IssueOptions
	}{
		{name: "нет signer", opts: pqt.IssueOptions{Codec: token.CodecJSON, Format: token.FormatText}},
		{name: "неизвестный codec", opts: pqt.IssueOptions{Signer: signer, Codec: "yaml", Format: token.FormatText}},
		{name: "неизвестный format", opts: pqt.IssueOptions{Signer: signer, Codec: token.CodecJSON, Format: "morse"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := pqt.Issue(token.Claims{}, tc.opts); !errors.Is(err, pqt.ErrInvalidOptions) {
				t.Fatalf("ожидали ErrInvalidOptions, получили %v", err)
			}
		})
	}
}

func TestValidate_RejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts pqt.ValidateOptions
	}{
		{name: "нет KeySource", opts: pqt.ValidateOptions{Format: token.FormatText}},
		{name: "неизвестный format", opts: pqt.ValidateOptions{
			KeySource: func(token.Header) (keys.PublicKey, error) { return nil, nil },
			Format:    "morse",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := pqt.Validate([]byte("anything"), tc.opts); !errors.Is(err, pqt.ErrInvalidOptions) {
				t.Fatalf("ожидали ErrInvalidOptions, получили %v", err)
			}
		})
	}
}

func TestValidate_RevokedToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Чёрный список: считаем, что наш jti отозван.
	blacklist := map[string]bool{sampleClaims(now).Jti: true}

	_, err = pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatText,
		Clock:     fixedClock(now),
		IsRevoked: func(jti string) bool { return blacklist[jti] },
	})
	if !errors.Is(err, pqt.ErrTokenRevoked) {
		t.Fatalf("ожидали ErrTokenRevoked, получили %v", err)
	}
}

func TestValidate_NilIsRevokedSkipsCheck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateECDSA()
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecJSON,
		Format: token.FormatText,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := pqt.Validate(tokenBytes, pqt.ValidateOptions{
		KeySource: staticKey(signer.Public()),
		Format:    token.FormatText,
		Clock:     fixedClock(now),
		// IsRevoked = nil — проверка должна полностью пропускаться.
	}); err != nil {
		t.Fatalf("Validate без IsRevoked: %v", err)
	}
}

func TestParse_ReadsHeaderWithoutVerification(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	signer, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateMLDSA: %v", err)
	}

	tokenBytes, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
		Signer: signer,
		Codec:  token.CodecCBOR,
		Format: token.FormatBinary,
		Kid:    "key-2026-04",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	header, claims, signature, signed, err := pqt.Parse(tokenBytes, token.FormatBinary)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if header.Alg != keys.AlgMLDSA65 {
		t.Fatalf("Header.Alg: got %s, want %s", header.Alg, keys.AlgMLDSA65)
	}
	if header.Kid != "key-2026-04" {
		t.Fatalf("Header.Kid: got %q", header.Kid)
	}
	if header.Enc != token.CodecCBOR {
		t.Fatalf("Header.Enc: got %s", header.Enc)
	}
	if claims.Sub != "user-42" {
		t.Fatalf("claims.Sub: got %q", claims.Sub)
	}
	if len(signature) == 0 {
		t.Fatal("signature пустая")
	}
	if len(signed) == 0 {
		t.Fatal("signed message пустой")
	}
}
