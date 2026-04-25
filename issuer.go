package pqt

import (
	"fmt"

	"pqt/token"
)

// Issue выпускает подписанный токен PQ-AT.
//
// Что происходит внутри:
//  1. Из Signer.Algorithm и опций собирается заголовок (Header).
//  2. Заголовок сериализуется в JSON, payload — в кодек из опций (json или cbor).
//  3. Подпись считается над склейкой H||P через Signer.Sign.
//  4. Три части собираются в указанный формат: текст (JWT-совместимый) или
//     компактный бинарь.
//
// Возвращаются байты готового токена. Если caller ждёт string для HTTP-заголовка
// Authorization: Bearer, он сам сделает string(b).
func Issue(claims token.Claims, opts IssueOptions) ([]byte, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	header := token.NewHeader(opts.Signer.Algorithm(), opts.Codec, opts.Kid)

	headerBytes, err := token.EncodeHeader(header)
	if err != nil {
		return nil, fmt.Errorf("pqt: выпуск, сериализация заголовка: %w", err)
	}

	payloadBytes, err := token.EncodePayload(claims, opts.Codec)
	if err != nil {
		return nil, fmt.Errorf("pqt: выпуск, сериализация payload: %w", err)
	}

	signature, err := opts.Signer.Sign(joinHeaderPayload(headerBytes, payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("pqt: выпуск, подпись: %w", err)
	}

	switch opts.Format {
	case token.FormatText:
		return []byte(token.SerializeText(headerBytes, payloadBytes, signature)), nil
	case token.FormatBinary:
		out, err := token.SerializeBinary(headerBytes, payloadBytes, signature)
		if err != nil {
			return nil, fmt.Errorf("pqt: выпуск, сборка бинарного формата: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: неизвестный формат %q", ErrInvalidOptions, opts.Format)
	}
}

// validate проверяет, что в IssueOptions заполнено всё необходимое.
func (o IssueOptions) validate() error {
	if o.Signer == nil {
		return fmt.Errorf("%w: не указан Signer", ErrInvalidOptions)
	}
	if !o.Codec.Valid() {
		return fmt.Errorf("%w: неизвестный кодек %q", ErrInvalidOptions, o.Codec)
	}
	if !o.Format.Valid() {
		return fmt.Errorf("%w: неизвестный формат %q", ErrInvalidOptions, o.Format)
	}
	return nil
}

// joinHeaderPayload готовит сообщение под подпись: просто склейка байтов
// заголовка и payload. Согласовано с разделом 2.2 спецификации PQ-AT
// («подпись считается над сериализованными заголовком и payload»).
func joinHeaderPayload(header, payload []byte) []byte {
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out
}
