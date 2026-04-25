package keys

import "errors"

// Маркерные ошибки криптослоя. Используются с errors.Is, чтобы код выше
// мог отличать виды ошибок без разбора текста сообщений.
var (
	// ErrInvalidSignature — подпись не прошла проверку.
	ErrInvalidSignature = errors.New("keys: invalid signature")

	// ErrInvalidKey — ключ битый или не подходит к заявленному алгоритму.
	ErrInvalidKey = errors.New("keys: invalid key")

	// ErrAlgMismatch — алгоритм ключа не совпадает с ожидаемым.
	ErrAlgMismatch = errors.New("keys: algorithm mismatch")

	// ErrUnsupportedAlg — указан неизвестный или не поддерживаемый алгоритм.
	ErrUnsupportedAlg = errors.New("keys: unsupported algorithm")

	// ErrMalformedSignature — байты подписи структурно битые. Например,
	// гибридная подпись короче, чем должна быть, или префикс длины
	// классической части указывает за пределы буфера.
	ErrMalformedSignature = errors.New("keys: malformed signature")
)
