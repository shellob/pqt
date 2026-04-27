package token

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// textSeparator — символ-разделитель между тремя частями текстового
// токена. Как и в JWT, это просто точка.
const textSeparator = "."

// SerializeText склеивает три части токена в текстовый формат,
// совместимый с JWT:
//
//	Base64url(header).Base64url(payload).Base64url(подпись)
//
// Каждая из трёх частей сначала кодируется в base64url — это та же
// base64, но с заменой '+' и '/' на '-' и '_' (чтобы результат можно
// было класть в URL без экранирования) и без хвостовых '='. Потом
// результаты соединяются через точку.
//
// Функция работает с уже готовыми байтами: содержимое заголовка и
// payload она не проверяет, подпись не считает. Если на вход подсунуть
// пустые или произвольные байты, они спокойно склеятся — смысловая
// валидация лежит выше по стеку, у функций EncodeHeader / EncodePayload
// и в самом pqt.Issue.
func SerializeText(header, payload, signature []byte) string {
	enc := base64.RawURLEncoding
	var sb strings.Builder
	// Заранее сообщаем builder'у итоговый размер, чтобы он не переаллоцировал
	// внутренний буфер по мере записи. Пара лишних строк ради экономии
	// одной аллокации в горячем пути выпуска токенов.
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

// ParseText делает обратное: разбивает текстовый токен по точкам на
// три части и каждую раскодирует из base64url обратно в байты.
// Возвращает три сырых блока — заголовок, payload и подпись — но
// никак не проверяет их содержимое. Что в этих байтах валидный JSON
// или валидная подпись, выяснится на следующих шагах разбора.
//
// Возможные ошибки (все с тегом ErrMalformed):
//   - На вход пришла строка, в которой не ровно две точки (значит,
//     частей не три) — это вообще не PQ-AT-токен в текстовом виде.
//   - Какая-то из трёх частей не валидный base64url (например, кто-то
//     случайно пропустил символ или подменил содержимое на ходу).
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
