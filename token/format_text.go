package token

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// textSeparator — точка между частями текстового токена, как в JWT.
const textSeparator = "."

// SerializeText собирает текстовый токен в формате, совместимом с JWT:
//
//	Base64url(header).Base64url(payload).Base64url(подпись)
//
// Функция работает с уже готовыми байтами и сама ничего не подписывает —
// это просто склейка через точку и base64url. Содержимое частей не проверяется:
// если на вход пришли пустые или произвольные байты, они спокойно склеятся.
// Смысл частей проверяет код выше — Header/Payload/Signature.
func SerializeText(header, payload, signature []byte) string {
	enc := base64.RawURLEncoding
	var sb strings.Builder
	sb.Grow(enc.EncodedLen(len(header)) +
		len(textSeparator) +
		enc.EncodedLen(len(payload)) +
		len(textSeparator) +
		enc.EncodedLen(len(signature)))
	sb.WriteString(enc.EncodeToString(header))
	sb.WriteString(textSeparator)
	sb.WriteString(enc.EncodeToString(payload))
	sb.WriteString(textSeparator)
	sb.WriteString(enc.EncodeToString(signature))
	return sb.String()
}

// ParseText делит текстовый токен по точкам и раскодирует каждую часть из
// Base64url. Возвращает три набора сырых байт — заголовок, payload и подпись.
// Сами байты не проверяются: смысловая валидация — выше по стеку.
//
// Если частей не три или какая-то из них не валидный Base64url — возвращается
// ошибка с тегом ErrMalformed.
func ParseText(token string) (header, payload, signature []byte, err error) {
	parts := strings.Split(token, textSeparator)
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: текстовый формат: ожидали 3 части через %q, получили %d",
			ErrMalformed, textSeparator, len(parts))
	}
	enc := base64.RawURLEncoding
	header, err = enc.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: текстовый формат: заголовок не Base64url: %w", ErrMalformed, err)
	}
	payload, err = enc.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: текстовый формат: payload не Base64url: %w", ErrMalformed, err)
	}
	signature, err = enc.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: текстовый формат: подпись не Base64url: %w", ErrMalformed, err)
	}
	return header, payload, signature, nil
}
