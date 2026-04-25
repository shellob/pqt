package token_test

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	ugorji "github.com/ugorji/go/codec"

	"pqt/token"
)

// Этот файл реализует сравнение CBOR-библиотек для главы 4.5 диссертации.
//
// Сравниваются два сценария:
//
//  1. «Из коробки»: типизированная token.Claims кодируется каждой либой со
//     своими настройками. fxamacker по cbor:"<n>,keyasint"-тегам даёт
//     CWT-стиль (целочисленные ключи 1..7). ugorji читает json-теги и кладёт
//     строковые имена ("sub", "iss", ...) — он не понимает keyasint. Это
//     честное сравнение того, что каждый кодек делает «по умолчанию», и
//     показывает реальное расхождение по размеру.
//
//  2. «На равных условиях»: обе либы кодируют map[int]any с теми же
//     числовыми ключами. CBOR-вывод у них совпадает побайтно — здесь
//     сравнивается чистая скорость кодека без разницы в стратегии разметки.
//
// Размеры выводов печатаются отдельным тестом TestCBORLibsOutputSize, чтобы
// сразу попадать в таблицу 4.5.

// sampleClaimsMap — те же claims, что и sampleClaims (см. codec_payload_test.go),
// но в виде map с CWT-ключами 1..7. Подаётся в обе CBOR-либы для сравнения
// «на равных условиях» — обе кодируют map[int]any одинаково и можно мерить
// чистую скорость кодека.
func sampleClaimsMap() map[int]any {
	c := sampleClaims()
	return map[int]any{
		1: c.Sub,
		2: c.Iss,
		3: c.Aud,
		4: c.Exp,
		5: c.Iat,
		6: c.Jti,
		7: c.Scope,
	}
}

// fxamackerEncMode — кодер fxamacker, собранный один раз. Совпадает по
// настройкам с production-кодом (см. codec_payload.go: cborCanonical).
// Бенчмарк обязан использовать ровно ту же конфигурацию, что и прод —
// иначе сравнение получится с систематическим смещением.
var fxamackerEncMode = func() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// fxamackerStrictDec — декодер fxamacker в строгом режиме, совпадает с
// production (DupMapKeyEnforcedAPF). Декод в бенчмарке через него, а не
// через cbor.Unmarshal по умолчанию — иначе бенч мерил бы не то, что
// реально работает в библиотеке.
var fxamackerStrictDec = func() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

func fxamackerEncode(v any) ([]byte, error) {
	return fxamackerEncMode.Marshal(v)
}

// ugorjiHandle — общий handle ugorji для всех вызовов в файле.
// Canonical=true даёт детерминированный порядок ключей; прямого аналога
// CanonicalEncOptions у ugorji нет, но для сравнения размеров и скорости
// этого достаточно.
var ugorjiHandle = func() *ugorji.CborHandle {
	h := &ugorji.CborHandle{}
	h.Canonical = true
	return h
}()

func ugorjiEncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := ugorji.NewEncoder(&buf, ugorjiHandle)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- Сценарий 1: типизированная Claims, каждая либа со своими настройками ---

func BenchmarkCBOREncode_Fxamacker_Claims(b *testing.B) {
	c := sampleClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fxamackerEncode(c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBOREncode_Ugorji_Claims(b *testing.B) {
	c := sampleClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ugorjiEncode(c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBORDecode_Fxamacker_Claims(b *testing.B) {
	data, err := fxamackerEncode(sampleClaims())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got token.Claims
		if err := fxamackerStrictDec.Unmarshal(data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBORDecode_Ugorji_Claims(b *testing.B) {
	data, err := ugorjiEncode(sampleClaims())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got token.Claims
		dec := ugorji.NewDecoderBytes(data, ugorjiHandle)
		if err := dec.Decode(&got); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Сценарий 2: map[int]any — одинаковый вход для обеих либ ---

func BenchmarkCBOREncode_Fxamacker_MapInt(b *testing.B) {
	m := sampleClaimsMap()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := fxamackerEncode(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBOREncode_Ugorji_MapInt(b *testing.B) {
	m := sampleClaimsMap()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ugorjiEncode(m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBORDecode_Fxamacker_MapInt(b *testing.B) {
	data, err := fxamackerEncode(sampleClaimsMap())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got map[int]any
		if err := fxamackerStrictDec.Unmarshal(data, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBORDecode_Ugorji_MapInt(b *testing.B) {
	data, err := ugorjiEncode(sampleClaimsMap())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got map[int]any
		dec := ugorji.NewDecoderBytes(data, ugorjiHandle)
		if err := dec.Decode(&got); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Размеры выводов ---

// TestCBORLibsOutputSize печатает сравнительные размеры CBOR-вывода.
// Запускать через `go test -v -run TestCBORLibsOutputSize ./token`.
// Никаких assert'ов нет: бенчмарковая «таблица» собирается из stdout этого
// теста и попадает в главу 4.5 диссертации.
func TestCBORLibsOutputSize(t *testing.T) {
	c := sampleClaims()
	m := sampleClaimsMap()

	type row struct {
		scenario string
		lib      string
		bytes    int
	}
	rows := []row{}

	if data, err := fxamackerEncode(c); err != nil {
		t.Fatalf("fxamacker Claims: %v", err)
	} else {
		rows = append(rows, row{"Claims (typed)", "fxamacker (keyasint)", len(data)})
	}
	if data, err := ugorjiEncode(c); err != nil {
		t.Fatalf("ugorji Claims: %v", err)
	} else {
		rows = append(rows, row{"Claims (typed)", "ugorji (json tags)", len(data)})
	}
	if data, err := fxamackerEncode(m); err != nil {
		t.Fatalf("fxamacker map: %v", err)
	} else {
		rows = append(rows, row{"map[int]any", "fxamacker", len(data)})
	}
	if data, err := ugorjiEncode(m); err != nil {
		t.Fatalf("ugorji map: %v", err)
	} else {
		rows = append(rows, row{"map[int]any", "ugorji", len(data)})
	}

	t.Log("\nРазмер CBOR-вывода для типового набора claims:")
	t.Logf("  %-20s %-25s %s", "Сценарий", "Библиотека", "Байт")
	for _, r := range rows {
		t.Logf("  %-20s %-25s %d", r.scenario, r.lib, r.bytes)
	}
}

// TestCBORLibsAgreeOnMapInt проверяет, что для map[int]any обе либы дают
// одинаковый байтовый вывод. Это важная санити-проверка: если результаты
// расходятся, значит как минимум одна из либ нарушает каноническое
// кодирование — и сравнение скоростей в сценарии 2 уже не на равных.
func TestCBORLibsAgreeOnMapInt(t *testing.T) {
	m := sampleClaimsMap()

	a, err := fxamackerEncode(m)
	if err != nil {
		t.Fatalf("fxamacker: %v", err)
	}
	u, err := ugorjiEncode(m)
	if err != nil {
		t.Fatalf("ugorji: %v", err)
	}
	if !bytes.Equal(a, u) {
		t.Logf("fxamacker: %x", a)
		t.Logf("ugorji:    %x", u)
		t.Fatalf("CBOR-вывод для одинакового map[int]any расходится: %d vs %d байт", len(a), len(u))
	}
}
