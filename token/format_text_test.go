package token_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"pqt/token"
)

func TestSerializeText_RoundTrip(t *testing.T) {
	t.Parallel()

	wantHeader := []byte(`{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json"}`)
	wantPayload := []byte(`{"sub":"user-1"}`)
	wantSig := []byte{0x01, 0x02, 0x03, 0x04, 0xfe, 0xff}

	serialized := token.SerializeText(wantHeader, wantPayload, wantSig)
	if strings.Count(serialized, ".") != 2 {
		t.Fatalf("ожидали ровно 2 точки в текстовом токене, получили %q", serialized)
	}

	gotHeader, gotPayload, gotSig, err := token.ParseText(serialized)
	if err != nil {
		t.Fatalf("ParseText: %v", err)
	}
	if !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("header round-trip не совпал: got %q, want %q", gotHeader, wantHeader)
	}
	if !bytes.Equal(gotPayload, wantPayload) {
		t.Fatalf("payload round-trip не совпал: got %q, want %q", gotPayload, wantPayload)
	}
	if !bytes.Equal(gotSig, wantSig) {
		t.Fatalf("signature round-trip не совпал: got %x, want %x", gotSig, wantSig)
	}
}

func TestSerializeText_NoBase64Padding(t *testing.T) {
	t.Parallel()
	// Один байт сигнатуры → без padding base64url выдаёт 2 символа.
	got := token.SerializeText([]byte("a"), []byte("b"), []byte{0xff})
	if strings.ContainsRune(got, '=') {
		t.Fatalf("текстовый токен не должен содержать padding '=' (RawURLEncoding): %s", got)
	}
}

func TestParseText_RejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
	}{
		{name: "одна часть", in: "AAAA"},
		{name: "две части", in: "AAAA.BBBB"},
		{name: "четыре части", in: "AAAA.BBBB.CCCC.DDDD"},
		{name: "невалидный base64 в header", in: "***.BBBB.CCCC"},
		{name: "невалидный base64 в payload", in: "AAAA.***.CCCC"},
		{name: "невалидный base64 в signature", in: "AAAA.BBBB.***"},
		{name: "пустая строка", in: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := token.ParseText(tc.in)
			if !errors.Is(err, token.ErrMalformed) {
				t.Fatalf("ожидали ErrMalformed, получили %v", err)
			}
		})
	}
}

func TestSerializeText_AllowsEmptyParts(t *testing.T) {
	t.Parallel()
	// Сами по себе пустые части — допустимы на уровне формата (валидация
	// содержимого — это уровень Header/Payload/Signature, не текстового кодера).
	got := token.SerializeText(nil, nil, nil)
	if got != ".." {
		t.Fatalf("ожидали \"..\" для трёх пустых частей, получили %q", got)
	}
	h, p, s, err := token.ParseText(got)
	if err != nil {
		t.Fatalf("ParseText на \"..\": %v", err)
	}
	if len(h) != 0 || len(p) != 0 || len(s) != 0 {
		t.Fatalf("ожидали три пустых среза, получили h=%v p=%v s=%v", h, p, s)
	}
}
