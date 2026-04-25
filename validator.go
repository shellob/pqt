package pqt

import (
	"fmt"
	"time"

	"pqt/token"
)

// Parse разбирает токен на части: заголовок, claims и сырые байты подписи.
// Подпись при этом НЕ проверяется — функция нужна для отладки и для случая,
// когда KeySource хочет посмотреть на header (например, на kid), чтобы выбрать
// ключ.
//
// Возвращает также сами байты H||P, над которыми считалась подпись — они
// нужны Validate, чтобы потом передать их в verifier.Verify.
//
// Срез signature ссылается на тот же массив, что и tokenBytes. Не меняй
// tokenBytes, пока эти срезы ещё используются.
func Parse(tokenBytes []byte, format token.Format) (
	header token.Header,
	claims token.Claims,
	signature []byte,
	signedMessage []byte,
	err error,
) {
	headerBytes, payloadBytes, sig, err := splitToken(tokenBytes, format)
	if err != nil {
		return token.Header{}, token.Claims{}, nil, nil, err
	}

	h, err := token.DecodeHeader(headerBytes)
	if err != nil {
		return token.Header{}, token.Claims{}, nil, nil, fmt.Errorf("pqt: разбор, заголовок: %w", err)
	}

	c, err := token.DecodePayload(payloadBytes, h.Enc)
	if err != nil {
		return token.Header{}, token.Claims{}, nil, nil, fmt.Errorf("pqt: разбор, payload: %w", err)
	}

	return h, c, sig, joinHeaderPayload(headerBytes, payloadBytes), nil
}

// Validate выполняет полную проверку токена: разбор, выбор ключа через
// KeySource, сверку алгоритма, проверку подписи и валидацию claims.
//
// Если всё в порядке — возвращает claims. Если что-то не так — конкретную
// ошибку с одним из тегов: ErrSignatureInvalid, ErrTokenExpired,
// ErrIssuerMismatch, ErrAudienceMismatch, ErrAlgMismatch, ErrKeyNotFound,
// ErrInvalidOptions, либо ошибки разбора с тегами token.ErrMalformed /
// token.ErrInvalidHeader.
//
// Не меняй буфер tokenBytes до возврата функции: внутри он не копируется,
// и срез байтов подписи ссылается на тот же массив. Если параллельно с
// Validate этот буфер кто-то перепишет — verify проверит уже не те байты,
// которые подписали.
func Validate(tokenBytes []byte, opts ValidateOptions) (token.Claims, error) {
	if err := opts.validate(); err != nil {
		return token.Claims{}, err
	}

	header, claims, signature, signedMessage, err := Parse(tokenBytes, opts.Format)
	if err != nil {
		return token.Claims{}, err
	}

	verifier, err := opts.KeySource(header)
	if err != nil {
		return token.Claims{}, fmt.Errorf("pqt: подбор ключа: %w", err)
	}
	if verifier == nil {
		return token.Claims{}, ErrKeyNotFound
	}

	if header.Alg != verifier.Algorithm() {
		return token.Claims{}, fmt.Errorf("%w: header.alg=%s, verifier.alg=%s",
			ErrAlgMismatch, header.Alg, verifier.Algorithm())
	}

	if err := verifier.Verify(signedMessage, signature); err != nil {
		return token.Claims{}, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	if err := validateClaims(claims, opts); err != nil {
		return token.Claims{}, err
	}

	return claims, nil
}

// validate проверяет, что в ValidateOptions заполнено всё необходимое.
func (o ValidateOptions) validate() error {
	if o.KeySource == nil {
		return fmt.Errorf("%w: не указан KeySource", ErrInvalidOptions)
	}
	if !o.Format.Valid() {
		return fmt.Errorf("%w: неизвестный формат %q", ErrInvalidOptions, o.Format)
	}
	return nil
}

// validateClaims сверяет утверждения с опциями: срок действия, ожидаемые
// issuer и audience.
func validateClaims(c token.Claims, opts ValidateOptions) error {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock()

	// По спецификации PQ-AT exp — обязательное поле. Токен без exp означает
	// «вечный access» — это всегда повод отвергнуть, даже если выпуск
	// случайно забыл проставить срок.
	if c.Exp == 0 {
		return fmt.Errorf("%w: exp отсутствует", ErrTokenExpired)
	}
	exp := time.Unix(c.Exp, 0)
	// Поблажка Leeway сдвигает «текущий момент» в прошлое: токен с
	// exp = now - 30s при Leeway = 60s ещё считается валидным.
	if now.Add(-opts.Leeway).After(exp) {
		return fmt.Errorf("%w: exp=%s, now=%s", ErrTokenExpired, exp, now)
	}

	if opts.ExpectedIssuer != "" && c.Iss != opts.ExpectedIssuer {
		return fmt.Errorf("%w: ожидали %q, получили %q",
			ErrIssuerMismatch, opts.ExpectedIssuer, c.Iss)
	}

	if opts.ExpectedAudience != "" && c.Aud != opts.ExpectedAudience {
		return fmt.Errorf("%w: ожидали %q, получили %q",
			ErrAudienceMismatch, opts.ExpectedAudience, c.Aud)
	}

	return nil
}

// splitToken разбирает токен на три части в соответствии с указанным форматом.
// Это тонкий helper над token.ParseText / token.ParseBinary; нужен только
// чтобы свести две функции к одному вызову.
func splitToken(tokenBytes []byte, format token.Format) (header, payload, signature []byte, err error) {
	switch format {
	case token.FormatText:
		return token.ParseText(string(tokenBytes))
	case token.FormatBinary:
		return token.ParseBinary(tokenBytes)
	default:
		return nil, nil, nil, fmt.Errorf("%w: неизвестный формат %q", ErrInvalidOptions, format)
	}
}
