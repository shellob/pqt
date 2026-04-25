package token_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"pqt/token"
)

func sampleClaims() token.Claims {
	return token.Claims{
		Sub:   "user-42",
		Iss:   "https://auth.example.com",
		Aud:   "https://api.example.com",
		Exp:   1_800_000_000,
		Iat:   1_700_000_000,
		Jti:   "01HXYZ-token-id",
		Scope: "read write",
	}
}

func TestEncodeDecodePayload_JSON_RoundTrip(t *testing.T) {
	t.Parallel()
	want := sampleClaims()

	data, err := token.EncodePayload(want, token.CodecJSON)
	if err != nil {
		t.Fatalf("EncodePayload(json): %v", err)
	}

	got, err := token.DecodePayload(data, token.CodecJSON)
	if err != nil {
		t.Fatalf("DecodePayload(json): %v", err)
	}
	if got != want {
		t.Fatalf("JSON round-trip не сохранил claims: got %+v, want %+v", got, want)
	}
}

func TestEncodeDecodePayload_CBOR_RoundTrip(t *testing.T) {
	t.Parallel()
	want := sampleClaims()

	data, err := token.EncodePayload(want, token.CodecCBOR)
	if err != nil {
		t.Fatalf("EncodePayload(cbor): %v", err)
	}

	got, err := token.DecodePayload(data, token.CodecCBOR)
	if err != nil {
		t.Fatalf("DecodePayload(cbor): %v", err)
	}
	if got != want {
		t.Fatalf("CBOR round-trip не сохранил claims: got %+v, want %+v", got, want)
	}
}

func TestEncodePayload_CBORUsesIntegerKeysWithCorrectMapping(t *testing.T) {
	t.Parallel()
	c := sampleClaims()
	data, err := token.EncodePayload(c, token.CodecCBOR)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}

	var raw map[int]any
	if err := cbor.Unmarshal(data, &raw); err != nil {
		t.Fatalf("CBOR должен парситься как map[int]any (целочисленные ключи): %v", err)
	}

	// Соответствие ключ→значение фиксирует спецификацию PQ-AT (1=sub..7=scope).
	// Проверка значениями, а не только наличием — иначе перестановка тэгов
	// между полями не будет поймана.
	wantMapping := map[int]any{
		1: c.Sub,
		2: c.Iss,
		3: c.Aud,
		4: c.Exp,
		5: c.Iat,
		6: c.Jti,
		7: c.Scope,
	}
	for k, want := range wantMapping {
		got, ok := raw[k]
		if !ok {
			t.Fatalf("ключ %d отсутствует в CBOR-выводе: %v", k, raw)
		}
		if !cborValueEqual(got, want) {
			t.Fatalf("ключ %d: got %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
}

// cborValueEqual сравнивает значения, учитывая, что CBOR-декодер
// для map[int]any может вернуть int64 или uint64 в зависимости от знака.
func cborValueEqual(got, want any) bool {
	if got == want {
		return true
	}
	if w, ok := want.(int64); ok {
		if g, ok := got.(uint64); ok && w >= 0 {
			return uint64(w) == g
		}
	}
	return false
}

func TestEncodePayload_CBORRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	// Сконструируем CBOR-байты руками: map с двумя ключами 1 (sub).
	// Заголовок 0xa2 — map из 2 элементов; 0x01 — целое 1; затем строка.
	dup := []byte{
		0xa2,                // map(2)
		0x01,                // key: 1
		0x63, 'a', 'a', 'a', // text(3) "aaa"
		0x01,                // key: 1 (дубликат)
		0x63, 'b', 'b', 'b', // text(3) "bbb"
	}

	if _, err := token.DecodePayload(dup, token.CodecCBOR); err == nil {
		t.Fatal("ожидали ошибку на дубликат ключа в CBOR-payload, получили nil")
	}
}

func TestEncodePayload_JSONIsCompact(t *testing.T) {
	t.Parallel()
	data, err := token.EncodePayload(sampleClaims(), token.CodecJSON)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}

	// Проверяем, что вывод — валидный JSON и без отступов (компактный).
	if !json.Valid(data) {
		t.Fatalf("JSON-вывод невалиден: %s", data)
	}
	if bytes.Contains(data, []byte("\n")) {
		t.Fatalf("JSON-вывод не должен содержать переводы строк: %s", data)
	}
}

func TestEncodePayload_OmitsEmptyFields(t *testing.T) {
	t.Parallel()
	c := token.Claims{Sub: "user-1"}

	jsonData, err := token.EncodePayload(c, token.CodecJSON)
	if err != nil {
		t.Fatalf("EncodePayload(json): %v", err)
	}
	if got := string(jsonData); got != `{"sub":"user-1"}` {
		t.Fatalf("ожидали компактный JSON с одним полем, получили: %s", got)
	}

	cborData, err := token.EncodePayload(c, token.CodecCBOR)
	if err != nil {
		t.Fatalf("EncodePayload(cbor): %v", err)
	}
	var raw map[int]any
	if err := cbor.Unmarshal(cborData, &raw); err != nil {
		t.Fatalf("CBOR unmarshal: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("ожидали ровно одно поле в CBOR (omitempty), получили: %v", raw)
	}
	if raw[1] != "user-1" {
		t.Fatalf("ожидали raw[1]=\"user-1\", получили: %v", raw)
	}
}

func TestEncodePayload_CBORDeterministic(t *testing.T) {
	t.Parallel()
	c := sampleClaims()

	first, err := token.EncodePayload(c, token.CodecCBOR)
	if err != nil {
		t.Fatalf("EncodePayload #1: %v", err)
	}
	second, err := token.EncodePayload(c, token.CodecCBOR)
	if err != nil {
		t.Fatalf("EncodePayload #2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("CBOR-вывод одних и тех же claims нестабилен:\n#1=%x\n#2=%x", first, second)
	}
}

func TestEncodePayload_RejectsUnknownCodec(t *testing.T) {
	t.Parallel()
	if _, err := token.EncodePayload(sampleClaims(), "yaml"); !errors.Is(err, token.ErrUnsupportedCodec) {
		t.Fatalf("ожидали ErrUnsupportedCodec, получили %v", err)
	}
	if _, err := token.DecodePayload([]byte(`{}`), "yaml"); !errors.Is(err, token.ErrUnsupportedCodec) {
		t.Fatalf("ожидали ErrUnsupportedCodec на decode, получили %v", err)
	}
}

func TestDecodePayload_RejectsMalformed(t *testing.T) {
	t.Parallel()
	if _, err := token.DecodePayload([]byte("{not json"), token.CodecJSON); !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrMalformed на JSON, получили %v", err)
	}
	if _, err := token.DecodePayload([]byte{0xff, 0xff}, token.CodecCBOR); !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrMalformed на CBOR, получили %v", err)
	}
}

func TestEncodePayload_CBORSmallerThanJSON(t *testing.T) {
	t.Parallel()
	c := sampleClaims()

	jsonData, err := token.EncodePayload(c, token.CodecJSON)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	cborData, err := token.EncodePayload(c, token.CodecCBOR)
	if err != nil {
		t.Fatalf("cbor: %v", err)
	}

	// Проверка целевой эффективности из раздела 2.4 диссертации:
	// CBOR должен быть заметно компактнее JSON. Эта проверка — sanity, цифры
	// для главы 4.5 собираются отдельным бенчмарком.
	if len(cborData) >= len(jsonData) {
		t.Fatalf("CBOR (%d) не должен быть >= JSON (%d) для типового набора claims",
			len(cborData), len(jsonData))
	}
}
