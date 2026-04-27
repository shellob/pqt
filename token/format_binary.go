package token

import (
	"encoding/binary"
	"fmt"
	"math"
)

// binaryLengthPrefixSize — сколько байт занимает запись длины одной
// секции. У нас это два байта, big-endian — то есть до 65535 байт
// (ограничение типа uint16). На практике этого хватает с большим
// запасом: заголовок токена занимает порядка 60-80 байт, payload —
// 100-200, подпись (для постквантовых режимов самая большая часть) —
// до 4-5 КБ.
const binaryLengthPrefixSize = 2

// SerializeBinary склеивает три части токена в один компактный
// бинарный поток по схеме:
//
//	[2 байта длины header][header][2 байта длины payload][payload][подпись]
//
// Все длины — uint16 в порядке байтов big-endian (старший байт первым).
// У подписи длины нет: она идёт последней, а размер её однозначно
// задаётся алгоритмом подписи (например, ровно 3309 байт для ML-DSA-65).
//
// Если заголовок или payload не помещаются в uint16 — возвращается
// ErrMalformed. Это сделано как явная защита от переполнения; в
// реальной жизни таких токенов не бывает (см. оценку выше), но
// проверка не повредит.
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

// ParseBinary разбирает бинарный токен обратно на три части — заголовок,
// payload и подпись. Длины первых двух частей берутся из их префиксов;
// всё, что осталось после payload, считается подписью.
//
// # Важная особенность: срезы ссылаются на тот же массив байт
//
// Возвращаемые header, payload и signature — это срезы исходного буфера
// data, без копирования. Это сделано ради скорости (см. бенчмарки
// в главе 4.5 диссертации: бинарный разбор быстрее текстового в три
// раза именно за счёт отсутствия аллокаций).
//
// Цена за это: пока подпись не проверена, нельзя менять содержимое
// data — иначе байты, по которым считается верификация, окажутся не
// теми, по которым считалась подпись. На практике это редкая ситуация
// (буфер обычно живёт в одной горутине), но важно держать в голове.
// Если контролировать неизменность data нельзя, нужно скопировать
// срезы вручную перед верификацией.
//
// # Ошибки
//
// Все возвращаются с тегом ErrMalformed. Возникают, если:
//   - не хватает байтов на префикс длины (data слишком короткий);
//   - длина секции, записанная в префиксе, выходит за пределы data
//     (заголовок или payload «не помещаются»);
//   - после payload не осталось байтов под подпись.
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

// readLengthPrefixed — общий код чтения одной секции вида
// [2 байта длины][байты]: применяется и для заголовка, и для payload.
//
// Возвращает: срез байтов секции (тот же массив data, без копирования)
// и позицию в data сразу после прочитанной секции — чтобы вызывающий
// мог продолжить чтение со следующего префикса.
//
// Параметр name нужен только для текста ошибки: «секция "заголовок"»
// или «секция "payload"», так что в логе видно, на чём именно сорвалось.
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
