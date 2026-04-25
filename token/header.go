package token

import (
	"bytes"
	"encoding/json"
	"fmt"

	"pqt/keys"
)

// TypePQAT — значение, которое обязательно должно быть в поле typ заголовка.
const TypePQAT = "PQ-AT"

// CurrentVersion — текущая версия формата токена. Заголовок с Ver вне диапазона
// [1, CurrentVersion] не принимается: декодер должен честно сказать, что не
// понимает формат, а не молча выпускать токен дальше.
const CurrentVersion = 1

// Header — заголовок токена PQ-AT (раздел 2.2 диссертации).
//
// Заголовок всегда сериализуется в JSON со строковыми именами полей. Поле Enc
// указывает, как кодируется payload — JSON или CBOR. Это именно encoding
// (формат записи), а не encryption: с одноимённым полем в JWE (RFC 7516) их
// путать не надо. Поле Kid — необязательное, нужно при ротации ключей через
// JWKS (этап 3).
//
// Список полей заголовка фиксированный: всё, чего нет в этой структуре,
// декодер отвергает. Так атакующему сложнее протащить лишнюю семантику в
// подписанный заголовок, а любое расширение формата вынуждено явно поднять
// номер версии CurrentVersion.
type Header struct {
	Alg keys.Alg `json:"alg"`
	Ver int      `json:"ver"`
	Typ string   `json:"typ"`
	Enc Codec    `json:"enc"`
	Kid string   `json:"kid,omitempty"`
}

// NewHeader собирает заголовок с разумными значениями по умолчанию:
// Typ = "PQ-AT", Ver = CurrentVersion. Параметрами идут только то, что
// действительно зависит от вызова: алгоритм, кодек payload и kid.
func NewHeader(alg keys.Alg, enc Codec, kid string) Header {
	return Header{
		Alg: alg,
		Ver: CurrentVersion,
		Typ: TypePQAT,
		Enc: enc,
		Kid: kid,
	}
}

// EncodeHeader сериализует заголовок в JSON. Перед записью проверяется,
// что поля имеют допустимые значения: алгоритм и кодек известны, версия —
// в диапазоне [1, CurrentVersion], типу — равен TypePQAT.
func EncodeHeader(h Header) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("token: encode header: %w", err)
	}
	return b, nil
}

// DecodeHeader разбирает JSON-заголовок и проверяет его поля.
//
// Декодер строгий: лишние поля отвергаются (DisallowUnknownFields), любые
// байты после закрывающей скобки — тоже. Без этого можно было бы спрятать в
// подписанные байты второй заголовок и потом «выбрать» нужный при разборе.
//
// Если JSON битый или есть лишние поля/мусор после объекта — возвращается
// ошибка с тегом ErrMalformed. Если JSON валидный, но значения полей
// неправильные (неизвестный alg/enc, версия вне диапазона, не тот typ) —
// ErrInvalidHeader.
func DecodeHeader(data []byte) (Header, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var h Header
	if err := dec.Decode(&h); err != nil {
		return Header{}, fmt.Errorf("%w: разбор JSON заголовка: %w", ErrMalformed, err)
	}
	if dec.More() {
		return Header{}, fmt.Errorf("%w: после объекта заголовка остались лишние данные", ErrMalformed)
	}
	if err := h.validate(); err != nil {
		return Header{}, err
	}
	return h, nil
}

// validate проверяет, что значения полей заголовка осмысленны.
func (h Header) validate() error {
	if !h.Alg.Valid() {
		return fmt.Errorf("%w: неизвестный alg %q", ErrInvalidHeader, h.Alg)
	}
	if !h.Enc.Valid() {
		return fmt.Errorf("%w: неизвестный enc %q", ErrInvalidHeader, h.Enc)
	}
	if h.Ver < 1 || h.Ver > CurrentVersion {
		return fmt.Errorf("%w: ver должен быть в диапазоне [1, %d], получено %d",
			ErrInvalidHeader, CurrentVersion, h.Ver)
	}
	if h.Typ != TypePQAT {
		return fmt.Errorf("%w: typ должен быть %q, получено %q", ErrInvalidHeader, TypePQAT, h.Typ)
	}
	return nil
}
