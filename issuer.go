package pqt

import (
	"fmt"

	"pqt/token"
)

// Issue выпускает подписанный токен PQ-AT по переданным claims (утверждениям
// о пользователе) и настройкам.
//
// Что делает функция, шаг за шагом:
//
//  1. Собирает заголовок токена. В заголовок попадают: алгоритм подписи —
//     берётся из ключа (Signer.Algorithm()), а не из опций, чтобы не было
//     возможности случайно собрать токен с одним alg в заголовке и другим
//     алгоритмом подписи; кодек payload (Codec) и идентификатор ключа (Kid)
//     из опций; версия формата и тип «PQ-AT» — константы.
//  2. Сериализует заголовок в JSON. Заголовок всегда в JSON, независимо от
//     Codec — это поле описывает только payload.
//  3. Сериализует claims в выбранный кодек (JSON или CBOR).
//  4. Считает подпись. Сообщение для подписи — просто склейка байтов
//     заголовка и payload (H || P). Подпись делает Signer; что внутри —
//     ECDSA, ML-DSA или гибрид — этот код знать не должен.
//  5. Склеивает три части (заголовок, payload, подпись) в итоговый
//     формат: текстовый (через точки и base64url, как JWT) или бинарный
//     (с длинами-префиксами, без base64).
//
// На выходе — байты готового токена. Если вызывающему коду нужен string
// (например, чтобы положить в HTTP-заголовок Authorization: Bearer),
// он сам сделает string(b) — мы возвращаем []byte, потому что бинарный
// формат содержит произвольные байты, не обязательно валидные как UTF-8.
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

// validate смотрит, что в IssueOptions заполнено всё, без чего нельзя
// выпустить токен. Возвращает ошибку с тегом ErrInvalidOptions —
// чтобы вызывающий код через errors.Is мог отличить «опции собраны
// неправильно» от «не получилось подписать».
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

// joinHeaderPayload готовит сообщение, над которым считается подпись:
// просто конкатенация байтов заголовка и payload, без разделителей.
// Это согласовано со спецификацией PQ-AT, раздел 2.2: «подпись
// вычисляется над склейкой сериализованных заголовка и полезной
// нагрузки».
//
// Никакого юникода, base64 или JSON-обёртки — Sign принимает плоские
// байты. На стороне Validate то же самое: при проверке восстанавливаются
// байты заголовка и payload и склеиваются в том же порядке.
func joinHeaderPayload(header, payload []byte) []byte {
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out
}
