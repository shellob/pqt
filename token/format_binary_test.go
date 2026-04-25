package token_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"pqt/token"
)

func TestSerializeBinary_RoundTrip(t *testing.T) {
	t.Parallel()

	wantHeader := []byte(`{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json"}`)
	wantPayload := []byte(`{"sub":"user-1","iss":"auth"}`)
	wantSig := bytes.Repeat([]byte{0xab}, 256)

	data, err := token.SerializeBinary(wantHeader, wantPayload, wantSig)
	if err != nil {
		t.Fatalf("SerializeBinary: %v", err)
	}

	// Проверка структуры по байтам.
	if got := binary.BigEndian.Uint16(data[0:2]); int(got) != len(wantHeader) {
		t.Fatalf("длина header в префиксе: got %d, want %d", got, len(wantHeader))
	}
	headerEnd := 2 + len(wantHeader)
	if got := binary.BigEndian.Uint16(data[headerEnd : headerEnd+2]); int(got) != len(wantPayload) {
		t.Fatalf("длина payload в префиксе: got %d, want %d", got, len(wantPayload))
	}

	gotHeader, gotPayload, gotSig, err := token.ParseBinary(data)
	if err != nil {
		t.Fatalf("ParseBinary: %v", err)
	}
	if !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("header round-trip не совпал")
	}
	if !bytes.Equal(gotPayload, wantPayload) {
		t.Fatalf("payload round-trip не совпал")
	}
	if !bytes.Equal(gotSig, wantSig) {
		t.Fatalf("signature round-trip не совпал")
	}
}

func TestSerializeBinary_NoExtraOverhead(t *testing.T) {
	t.Parallel()

	header := bytes.Repeat([]byte{'h'}, 80)
	payload := bytes.Repeat([]byte{'p'}, 120)
	signature := bytes.Repeat([]byte{'s'}, 3309)

	data, err := token.SerializeBinary(header, payload, signature)
	if err != nil {
		t.Fatalf("SerializeBinary: %v", err)
	}

	want := 2 + len(header) + 2 + len(payload) + len(signature)
	if len(data) != want {
		t.Fatalf("ожидали ровно %d байт (2+H+2+P+Sig), получили %d", want, len(data))
	}
}

func TestSerializeBinary_RejectsTooLong(t *testing.T) {
	t.Parallel()

	tooLong := make([]byte, 1<<16) // 65536 > MaxUint16
	if _, err := token.SerializeBinary(tooLong, nil, nil); !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrMalformed для слишком длинного header, получили %v", err)
	}
	if _, err := token.SerializeBinary(nil, tooLong, nil); !errors.Is(err, token.ErrMalformed) {
		t.Fatalf("ожидали ErrMalformed для слишком длинного payload, получили %v", err)
	}
}

func TestParseBinary_RejectsMalformed(t *testing.T) {
	t.Parallel()

	headerLenPrefix := []byte{0x00, 0x05} // длина header = 5
	header := []byte("HHHHH")
	payloadLenPrefix := []byte{0x00, 0x03}
	payload := []byte("PPP")

	cases := []struct {
		name string
		data []byte
	}{
		{name: "пустой буфер", data: nil},
		{name: "обрезан префикс header", data: []byte{0x00}},
		{name: "header обрезан", data: append(append([]byte{}, headerLenPrefix...), 'H', 'H')},
		{
			name: "обрезан префикс payload",
			data: append(append([]byte{}, headerLenPrefix...), header...),
		},
		{
			name: "payload обрезан",
			data: bytes.Join([][]byte{headerLenPrefix, header, payloadLenPrefix, []byte("PP")}, nil),
		},
		{
			name: "подпись отсутствует",
			data: bytes.Join([][]byte{headerLenPrefix, header, payloadLenPrefix, payload}, nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := token.ParseBinary(tc.data)
			if !errors.Is(err, token.ErrMalformed) {
				t.Fatalf("ожидали ErrMalformed, получили %v", err)
			}
		})
	}
}

func TestParseBinary_AllowsEmptyHeaderAndPayload(t *testing.T) {
	t.Parallel()
	// Структурно формат разрешает пустой header/payload — содержательная
	// валидация выполняется на уровне Header/Payload, а не бинарного кодера.
	data := bytes.Join([][]byte{
		{0x00, 0x00}, // длина header = 0
		{0x00, 0x00}, // длина payload = 0
		{0x42},       // signature = 1 байт
	}, nil)

	h, p, s, err := token.ParseBinary(data)
	if err != nil {
		t.Fatalf("ParseBinary: %v", err)
	}
	if len(h) != 0 || len(p) != 0 || !bytes.Equal(s, []byte{0x42}) {
		t.Fatalf("ожидали (h=пусто, p=пусто, s=[0x42]), получили (h=%x, p=%x, s=%x)", h, p, s)
	}
}

func TestParseBinary_AliasesInputBuffer(t *testing.T) {
	t.Parallel()
	// Тест закрепляет правило: ParseBinary не копирует — возвращённые срезы
	// ссылаются на тот же массив data. Если кто-то поменяет реализацию на
	// копирование, не обновив godoc, этот тест упадёт и заставит обновить
	// документацию явно.
	data, err := token.SerializeBinary(
		[]byte(`{"alg":"ecdsa-p256","ver":1,"typ":"PQ-AT","enc":"json"}`),
		[]byte(`{"sub":"u-1"}`),
		[]byte{0xaa, 0xbb, 0xcc, 0xdd},
	)
	if err != nil {
		t.Fatalf("SerializeBinary: %v", err)
	}

	_, _, sig, err := token.ParseBinary(data)
	if err != nil {
		t.Fatalf("ParseBinary: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature пустая, тест не имеет смысла")
	}

	// Мутация исходного буфера должна отразиться в ранее возвращённом sig.
	original := sig[len(sig)-1]
	data[len(data)-1] ^= 0xff
	if sig[len(sig)-1] == original {
		t.Fatal("ParseBinary копирует signature — это расходится с тем, что написано в godoc; либо верните то, как было, либо обновите документацию")
	}
}

func TestSerializeBinary_TextSizeAdvantage(t *testing.T) {
	t.Parallel()
	// Sanity-проверка: бинарный формат обязан быть строго меньше текстового
	// для одинаковых частей за счёт отсутствия Base64url (33% накладных).
	header := bytes.Repeat([]byte{'h'}, 60)
	payload := bytes.Repeat([]byte{'p'}, 120)
	signature := bytes.Repeat([]byte{'s'}, 3309)

	binData, err := token.SerializeBinary(header, payload, signature)
	if err != nil {
		t.Fatalf("SerializeBinary: %v", err)
	}
	textData := token.SerializeText(header, payload, signature)

	if len(binData) >= len(textData) {
		t.Fatalf("бинарный (%d) не должен быть >= текстового (%d) для одинаковых частей",
			len(binData), len(textData))
	}
	// Текстовый содержит две точки-разделителя — простой признак, что мы
	// действительно сравнили с правильным форматом.
	if strings.Count(textData, ".") != 2 {
		t.Fatalf("текстовый токен должен иметь 2 точки, получили %q", textData)
	}
}
