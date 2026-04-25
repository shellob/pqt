package token

import "errors"

// Маркерные ошибки пакета. Используются вместе с errors.Is, чтобы код выше
// (Issuer, Validator, HTTP-обработчики) мог отличать виды ошибок без разбора
// текста сообщений.
var (
	// ErrMalformed — токен или одна из его частей структурно битые: не сходится
	// число секций, обрезанные длины, невалидный base64 и т. п.
	ErrMalformed = errors.New("token: malformed")

	// ErrInvalidHeader — заголовок прочитался, но в нём недопустимые значения
	// (неизвестный alg/enc, ver вне диапазона, не тот typ).
	ErrInvalidHeader = errors.New("token: invalid header")

	// ErrUnsupportedCodec — указанный кодек payload не поддерживается.
	ErrUnsupportedCodec = errors.New("token: unsupported codec")
)
