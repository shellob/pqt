package pqt_test

import (
	"testing"
	"time"

	"pqt"
	"pqt/keys"
	"pqt/token"
)

// addValidTextSeeds добавляет несколько валидных текстовых токенов в фаззер,
// чтобы у движка было от чего отталкиваться при мутации входа.
func addValidTextSeeds(f *testing.F) {
	f.Helper()
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	// ECDSA + JSON
	if k, err := keys.GenerateECDSA(); err == nil {
		if b, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
			Signer: k, Codec: token.CodecJSON, Format: token.FormatText,
		}); err == nil {
			f.Add(string(b))
		}
	}

	// MLDSA-65 + CBOR
	if k, err := keys.GenerateMLDSA(keys.AlgMLDSA65); err == nil {
		if b, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
			Signer: k, Codec: token.CodecCBOR, Format: token.FormatText,
		}); err == nil {
			f.Add(string(b))
		}
	}

	// Запасные, явно невалидные seed'ы — чтобы фаззер исследовал и path для
	// невалидных токенов.
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("AAAA.BBBB.CCCC")
	f.Add("AAAA.BBBB")
	f.Add("...")
}

// addValidBinarySeeds — то же самое для бинарного формата.
func addValidBinarySeeds(f *testing.F) {
	f.Helper()
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	if k, err := keys.GenerateECDSA(); err == nil {
		if b, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
			Signer: k, Codec: token.CodecJSON, Format: token.FormatBinary,
		}); err == nil {
			f.Add(b)
		}
	}

	if k, err := keys.GenerateMLDSA(keys.AlgMLDSA65); err == nil {
		if b, err := pqt.Issue(sampleClaims(now), pqt.IssueOptions{
			Signer: k, Codec: token.CodecCBOR, Format: token.FormatBinary,
		}); err == nil {
			f.Add(b)
		}
	}

	// Заведомо невалидные.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
}

// FuzzParseText бьёт случайные строки в pqt.Parse в текстовом формате.
// От разбора требуется одно: не паниковать и не зависать на любом входе.
// Любая ошибка парсинга — нормально и ожидаемо; падение — нет.
func FuzzParseText(f *testing.F) {
	addValidTextSeeds(f)

	f.Fuzz(func(_ *testing.T, input string) {
		// Игнорируем возвращаемые значения — нас интересует только то,
		// что вызов отрабатывает без паники.
		_, _, _, _, _ = pqt.Parse([]byte(input), token.FormatText)
	})
}

// FuzzParseBinary то же самое для бинарного формата.
func FuzzParseBinary(f *testing.F) {
	addValidBinarySeeds(f)

	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _, _, _, _ = pqt.Parse(input, token.FormatBinary)
	})
}

// FuzzValidateText проверяет всю цепочку Validate — включая verify подписи —
// на случайных строках. Нам тоже важно только отсутствие паник: подпись
// случайно угаданной не будет, поэтому Validate почти всегда будет возвращать
// ошибку, и это правильно.
func FuzzValidateText(f *testing.F) {
	addValidTextSeeds(f)

	signer, err := keys.GenerateECDSA()
	if err != nil {
		f.Fatalf("GenerateECDSA: %v", err)
	}
	pub := signer.Public()

	f.Fuzz(func(_ *testing.T, input string) {
		_, _ = pqt.Validate([]byte(input), pqt.ValidateOptions{
			KeySource: func(token.Header) (keys.PublicKey, error) { return pub, nil },
			Format:    token.FormatText,
			Clock:     func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) },
		})
	})
}

// FuzzValidateBinary — аналогично для бинарного формата.
func FuzzValidateBinary(f *testing.F) {
	addValidBinarySeeds(f)

	signer, err := keys.GenerateECDSA()
	if err != nil {
		f.Fatalf("GenerateECDSA: %v", err)
	}
	pub := signer.Public()

	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = pqt.Validate(input, pqt.ValidateOptions{
			KeySource: func(token.Header) (keys.PublicKey, error) { return pub, nil },
			Format:    token.FormatBinary,
			Clock:     func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) },
		})
	})
}
