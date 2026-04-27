package bench_test

import (
	"testing"
	"time"

	"pqt"
	"pqt/keys"
	"pqt/token"
)

// Бенчмарки формат-матрицы для главы 4.5: 3 алгоритма × 2 кодека × 2 формата.
//
// Зачем три бенчмарка вместо одного:
//   - BenchmarkIssue_FormatMatrix     — полный выпуск: сериализация + подпись.
//   - BenchmarkValidate_FormatMatrix  — полная проверка: парсинг + verify + claims.
//   - BenchmarkParse_FormatMatrix     — только pqt.Parse (без verify), вычленяет
//     стоимость собственно формата без вклада криптографии.
//
// Команды воспроизведения:
//
//	go test -bench=BenchmarkIssue_FormatMatrix    -benchmem -run=^$ -benchtime=2s ./internal/bench/...
//	go test -bench=BenchmarkValidate_FormatMatrix -benchmem -run=^$ -benchtime=2s ./internal/bench/...
//	go test -bench=BenchmarkParse_FormatMatrix    -benchmem -run=^$ -benchtime=2s ./internal/bench/...
//	go test -v -run=TestFormatMatrix_Sizes ./internal/bench/...

// matrixCase — одна точка матрицы.
type matrixCase struct {
	alg    string
	codec  token.Codec
	format token.Format
}

// matrix перечисляет все 12 точек 3 alg × 2 codec × 2 format.
// Алгоритмы выбраны из спецификации PQ-AT (раздел 2.3): ecdsa-p256 для
// обратной совместимости, mldsa65 как целевой, hybrid65 — переходный режим.
var matrix = []matrixCase{
	{"ecdsa-p256", token.CodecJSON, token.FormatText},
	{"ecdsa-p256", token.CodecJSON, token.FormatBinary},
	{"ecdsa-p256", token.CodecCBOR, token.FormatText},
	{"ecdsa-p256", token.CodecCBOR, token.FormatBinary},
	{"mldsa65", token.CodecJSON, token.FormatText},
	{"mldsa65", token.CodecJSON, token.FormatBinary},
	{"mldsa65", token.CodecCBOR, token.FormatText},
	{"mldsa65", token.CodecCBOR, token.FormatBinary},
	{"hybrid-mldsa65", token.CodecJSON, token.FormatText},
	{"hybrid-mldsa65", token.CodecJSON, token.FormatBinary},
	{"hybrid-mldsa65", token.CodecCBOR, token.FormatText},
	{"hybrid-mldsa65", token.CodecCBOR, token.FormatBinary},
}

// makeSigner возвращает приватный ключ для каждого алгоритма матрицы.
// Для ECDSA генерируется новая пара, для ML-DSA-65 — отдельная, для гибрида —
// composite. Один и тот же набор claims кормится во все три, чтобы единственная
// переменная в эксперименте — это собственно alg/codec/format.
func makeSigner(b testHelper, alg string) keys.PrivateKey {
	b.Helper()
	switch alg {
	case "ecdsa-p256":
		k, err := keys.GenerateECDSA()
		if err != nil {
			b.Fatalf("ecdsa: %v", err)
		}
		return k
	case "mldsa65":
		k, err := keys.GenerateMLDSA(keys.AlgMLDSA65)
		if err != nil {
			b.Fatalf("mldsa65: %v", err)
		}
		return k
	case "hybrid-mldsa65":
		k, err := keys.GenerateHybrid(keys.AlgMLDSA65)
		if err != nil {
			b.Fatalf("hybrid65: %v", err)
		}
		return k
	default:
		b.Fatalf("неизвестный алгоритм %q", alg)
		return nil
	}
}

func caseName(c matrixCase) string {
	return c.alg + "_" + string(c.codec) + "_" + string(c.format)
}

func BenchmarkIssue_FormatMatrix(b *testing.B) {
	c := sampleClaims()
	for _, m := range matrix {
		b.Run(caseName(m), func(b *testing.B) {
			signer := makeSigner(b, m.alg)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := pqt.Issue(c, pqt.IssueOptions{
					Signer: signer,
					Codec:  m.codec,
					Format: m.format,
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkValidate_FormatMatrix(b *testing.B) {
	c := sampleClaims()
	clock := func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) }
	for _, m := range matrix {
		b.Run(caseName(m), func(b *testing.B) {
			signer := makeSigner(b, m.alg)
			tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
				Signer: signer,
				Codec:  m.codec,
				Format: m.format,
			})
			if err != nil {
				b.Fatal(err)
			}
			pub := signer.Public()
			opts := pqt.ValidateOptions{
				KeySource:        func(_ token.Header) (keys.PublicKey, error) { return pub, nil },
				Format:           m.format,
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
		})
	}
}

func BenchmarkParse_FormatMatrix(b *testing.B) {
	c := sampleClaims()
	for _, m := range matrix {
		b.Run(caseName(m), func(b *testing.B) {
			signer := makeSigner(b, m.alg)
			tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
				Signer: signer,
				Codec:  m.codec,
				Format: m.format,
			})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, _, _, err := pqt.Parse(tokBytes, m.format); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestFormatMatrix_Sizes печатает реальный размер выпущенного токена для всех
// 12 точек матрицы. Цифры идут в таблицу 4.5 диссертации.
func TestFormatMatrix_Sizes(t *testing.T) {
	c := sampleClaims()

	type row struct {
		name  string
		bytes int
	}
	rows := make([]row, 0, len(matrix))

	for _, m := range matrix {
		signer := makeSigner(t, m.alg)
		tokBytes, err := pqt.Issue(c, pqt.IssueOptions{
			Signer: signer,
			Codec:  m.codec,
			Format: m.format,
		})
		if err != nil {
			t.Fatalf("%s: %v", caseName(m), err)
		}
		rows = append(rows, row{name: caseName(m), bytes: len(tokBytes)})
	}

	t.Log("\nРазмеры токена для всех точек формат-матрицы:")
	t.Logf("  %-40s %s", "Сценарий", "Байт")
	for _, r := range rows {
		t.Logf("  %-40s %d", r.name, r.bytes)
	}
}
