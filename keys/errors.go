package keys

import "errors"

// Sentinel-ошибки криптослоя. Используются с errors.Is для классификации
// ошибок подписи и верификации в верхних слоях.
var (
	// ErrInvalidSignature — подпись не прошла верификацию.
	ErrInvalidSignature = errors.New("keys: invalid signature")

	// ErrInvalidKey — ключ повреждён или несовместим с заявленным алгоритмом.
	ErrInvalidKey = errors.New("keys: invalid key")

	// ErrAlgMismatch — алгоритм ключа не соответствует ожидаемому.
	ErrAlgMismatch = errors.New("keys: algorithm mismatch")

	// ErrUnsupportedAlg — указан неизвестный или неподдерживаемый алгоритм.
	ErrUnsupportedAlg = errors.New("keys: unsupported algorithm")

	// ErrMalformedSignature — формат подписи нарушен (например, не удаётся
	// разобрать гибридный layout).
	ErrMalformedSignature = errors.New("keys: malformed signature")
)
