package token_test

import (
	"errors"
	"strings"
	"testing"

	"pqt/keys"
	"pqt/token"
)

func TestEncodeDecodeHeader_RoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		h    token.Header
	}{
		{
			name: "ecdsa без kid",
			h:    token.NewHeader(keys.AlgECDSAP256, token.CodecJSON, ""),
		},
		{
			name: "mldsa65 cbor с kid",
			h:    token.NewHeader(keys.AlgMLDSA65, token.CodecCBOR, "key-2026-04"),
		},
		{
			name: "гибрид cbor без kid",
			h:    token.NewHeader(keys.AlgHybridECDSAMLDSA65, token.CodecCBOR, ""),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := token.EncodeHeader(tc.h)
			if err != nil {
				t.Fatalf("EncodeHeader: %v", err)
			}

			got, err := token.DecodeHeader(data)
			if err != nil {
				t.Fatalf("DecodeHeader: %v", err)
			}
			if got != tc.h {
				t.Fatalf("round-trip изменил заголовок: got %+v, want %+v", got, tc.h)
			}
		})
	}
}

func TestEncodeHeader_OmitsEmptyKid(t *testing.T) {
	t.Parallel()
	h := token.NewHeader(keys.AlgECDSAP256, token.CodecJSON, "")
	data, err := token.EncodeHeader(h)
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	if strings.Contains(string(data), `"kid"`) {
		t.Fatalf("ожидали отсутствие поля kid в JSON для пустого Kid, получили: %s", data)
	}
}

func TestEncodeHeader_RejectsInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		h    token.Header
	}{
		{
			name: "неизвестный alg",
			h:    token.Header{Alg: "rsa-pkcs1", Ver: 1, Typ: token.TypePQAT, Enc: token.CodecJSON},
		},
		{
			name: "неизвестный enc",
			h:    token.Header{Alg: keys.AlgECDSAP256, Ver: 1, Typ: token.TypePQAT, Enc: "yaml"},
		},
		{
			name: "ver = 0",
			h:    token.Header{Alg: keys.AlgECDSAP256, Ver: 0, Typ: token.TypePQAT, Enc: token.CodecJSON},
		},
		{
			name: "пустой typ",
			h:    token.Header{Alg: keys.AlgECDSAP256, Ver: 1, Typ: "", Enc: token.CodecJSON},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := token.EncodeHeader(tc.h); !errors.Is(err, token.ErrInvalidHeader) {
				t.Fatalf("ожидали ErrInvalidHeader, получили %v", err)
			}
		})
	}
}

func TestDecodeHeader_RejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	_, err := token.DecodeHeader([]byte("{not json"))
	if !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrMalformed на сломанный JSON, получили %v", err)
	}
}

func TestDecodeHeader_RejectsLogicallyInvalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		json string
	}{
		{
			name: "неизвестный alg",
			json: `{"alg":"rsa-pkcs1","ver":1,"typ":"PQ-AT","enc":"json"}`,
		},
		{
			name: "ver < 1",
			json: `{"alg":"ecdsa-p256","ver":0,"typ":"PQ-AT","enc":"json"}`,
		},
		{
			name: "ver > CurrentVersion",
			json: `{"alg":"ecdsa-p256","ver":99,"typ":"PQ-AT","enc":"json"}`,
		},
		{
			name: "typ ≠ PQ-AT",
			json: `{"alg":"ecdsa-p256","ver":1,"typ":"JWT","enc":"json"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := token.DecodeHeader([]byte(tc.json)); !errors.Is(err, token.ErrInvalidHeader) {
				t.Fatalf("ожидали ErrInvalidHeader, получили %v", err)
			}
		})
	}
}

func TestDecodeHeader_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	// Header — закрытое множество полей. Любое неизвестное поле — структурная
	// ошибка; иначе атакующий может прятать дополнительную семантику в
	// подписанном заголовке.
	js := `{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json","crit":"nope"}`
	_, err := token.DecodeHeader([]byte(js))
	if !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrMalformed на неизвестное поле, получили %v", err)
	}
}

func TestDecodeHeader_RejectsTrailingData(t *testing.T) {
	t.Parallel()
	// Trailing data после закрывающей скобки — структурная ошибка. Иначе в
	// одном подписанном байтовом отрезке могут жить два разных Header'а.
	// Допустимый whitespace по RFC 8259 в конце не считается атакой:
	// он меняет байты заголовка и автоматически ломает verify подписи.
	cases := []string{
		`{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json"}{"alg":"evil"}`,
		`{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json"}   garbage`,
		`{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json"}null`,
	}
	for _, in := range cases {
		_, err := token.DecodeHeader([]byte(in))
		if !errors.Is(err, token.ErrMalformed) {
			t.Fatalf("ожидали ErrMalformed на trailing data %q, получили %v", in, err)
		}
	}
}
