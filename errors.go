package pqt

import "errors"

// Маркерные ошибки публичного API. Используются с errors.Is, чтобы
// HTTP-обработчики, логгеры и тесты могли отличать виды ошибок без
// разбора текста сообщений.
var (
	// ErrSignatureInvalid — подпись токена не прошла проверку. Возвращается,
	// когда verify над H||P даёт false. Это всегда повод отвергнуть токен.
	ErrSignatureInvalid = errors.New("pqt: signature is invalid")

	// ErrTokenExpired — текущее время превышает claim exp с учётом Leeway.
	ErrTokenExpired = errors.New("pqt: token expired")

	// ErrIssuerMismatch — claim iss не совпадает с ExpectedIssuer из опций.
	ErrIssuerMismatch = errors.New("pqt: issuer mismatch")

	// ErrAudienceMismatch — claim aud не совпадает с ExpectedAudience из опций.
	ErrAudienceMismatch = errors.New("pqt: audience mismatch")

	// ErrAlgMismatch — алгоритм в заголовке токена не совпадает с алгоритмом
	// ключа, который вернул KeySource. Закрывает класс атак alg-confusion:
	// злоумышленник подменяет header.alg, надеясь подсунуть подпись более
	// слабого алгоритма под видом ожидаемого.
	ErrAlgMismatch = errors.New("pqt: header alg does not match verifier algorithm")

	// ErrKeyNotFound — KeySource не смог вернуть ключ для этого заголовка.
	// Например, kid из header'а отсутствует в JWKS-наборе.
	ErrKeyNotFound = errors.New("pqt: verification key not found")

	// ErrInvalidOptions — переданные опции выпуска или проверки несовместимы
	// (например, в IssueOptions нет Signer'а, или Format/Codec не указаны).
	ErrInvalidOptions = errors.New("pqt: invalid options")
)
