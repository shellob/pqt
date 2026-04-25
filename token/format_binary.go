package token

import (
	"encoding/binary"
	"fmt"
	"math"
)

// binaryLengthPrefixSize — сколько байт отведено под длину секции (uint16,
// big-endian). Это значит, что заголовок и полезная нагрузка не должны быть
// длиннее 65535 байт. Для обычного токена с десятком claims этого хватает с
// большим запасом.
const binaryLengthPrefixSize = 2

// SerializeBinary склеивает три части токена в один бинарный поток по схеме:
//
//	[2 байта длины header][header][2 байта длины payload][payload][подпись]
//
// Все длины пишутся в big-endian. У подписи длины нет — она всегда идёт
// последней, а её размер однозначно задан алгоритмом.
func SerializeBinary(header, payload, signature []byte) ([]byte, error) {
	if len(header) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: бинарный формат: заголовок слишком длинный (%d > %d)",
			ErrMalformed, len(header), math.MaxUint16)
	}
	if len(payload) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: бинарный формат: payload слишком длинный (%d > %d)",
			ErrMalformed, len(payload), math.MaxUint16)
	}

	out := make([]byte, binaryLengthPrefixSize+len(header)+binaryLengthPrefixSize+len(payload)+len(signature))
	pos := 0

	binary.BigEndian.PutUint16(out[pos:], uint16(len(header)&math.MaxUint16))
	pos += binaryLengthPrefixSize
	pos += copy(out[pos:], header)

	binary.BigEndian.PutUint16(out[pos:], uint16(len(payload)&math.MaxUint16))
	pos += binaryLengthPrefixSize
	pos += copy(out[pos:], payload)

	copy(out[pos:], signature)
	return out, nil
}

// ParseBinary разбирает бинарный токен на три части — header, payload и подпись.
//
// Важно: возвращаемые срезы — это куски того же массива data, без копирования.
// Пока подпись не проверена, не меняй data: иначе байты, которые подписали,
// и байты, которые в итоге проверяются, будут разными. Так сделано специально,
// чтобы бенчмарки из главы 4 диссертации измеряли формат, а не лишние копии.
// Если гарантировать неизменность data нельзя — скопируй срезы сам перед
// проверкой подписи.
//
// Если данные обрезаны (не хватает байт на длину секции, секция короче
// заявленной длины, нет места под подпись) — возвращается ошибка с тегом
// ErrMalformed.
func ParseBinary(data []byte) (header, payload, signature []byte, err error) {
	pos := 0

	header, pos, err = readLengthPrefixed(data, pos, "заголовок")
	if err != nil {
		return nil, nil, nil, err
	}
	payload, pos, err = readLengthPrefixed(data, pos, "payload")
	if err != nil {
		return nil, nil, nil, err
	}
	if pos >= len(data) {
		return nil, nil, nil, fmt.Errorf("%w: бинарный формат: подпись отсутствует", ErrMalformed)
	}
	signature = data[pos:]
	return header, payload, signature, nil
}

// readLengthPrefixed читает одну секцию вида [2 байта длины][байты] начиная
// с позиции pos. Возвращает сами байты (срез того же массива data) и позицию
// сразу после секции.
func readLengthPrefixed(data []byte, pos int, name string) ([]byte, int, error) {
	if pos+binaryLengthPrefixSize > len(data) {
		return nil, 0, fmt.Errorf("%w: бинарный формат: нет места под длину секции %q",
			ErrMalformed, name)
	}
	length := int(binary.BigEndian.Uint16(data[pos:]))
	pos += binaryLengthPrefixSize
	end := pos + length
	if end > len(data) {
		return nil, 0, fmt.Errorf("%w: бинарный формат: секция %q обрезана (нужно %d байт, осталось %d)",
			ErrMalformed, name, length, len(data)-pos)
	}
	return data[pos:end], end, nil
}
