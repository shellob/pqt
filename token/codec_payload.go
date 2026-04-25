package token

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// EncodePayload сериализует Claims выбранным кодеком.
//
// Для CodecCBOR используется канонический режим из библиотеки fxamacker/cbor:
// ключи сортируются в одном и том же порядке, целые числа пишутся минимально
// возможным числом байт. Это даёт байт-в-байт одинаковый вывод для одних и тех
// же claims, что важно для подписи. У нас в claims нет float-полей, поэтому
// результат совпадает с тем, что даёт «детерминированное» кодирование из
// RFC 8949 §4.2.1.
//
// Для CodecJSON — обычный encoding/json. Порядок полей в JSON определяется
// порядком объявления полей в структуре Claims, так что вывод тоже стабильный.
func EncodePayload(c Claims, codec Codec) ([]byte, error) {
	switch codec {
	case CodecJSON:
		b, err := json.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("token: сериализация payload (json): %w", err)
		}
		return b, nil
	case CodecCBOR:
		b, err := cborCanonical.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("token: сериализация payload (cbor): %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCodec, codec)
	}
}

// DecodePayload разбирает байты payload в Claims согласно выбранному кодеку.
//
// Для CodecCBOR декодер строгий: если в map встречается дубликат ключа —
// возвращается ошибка (DupMapKeyEnforcedAPF). Так мы закрываем класс атак,
// когда в один и тот же подписанный поток байт кладут два значения одного
// claim, а разные верификаторы выбирают разные значения.
//
// Если данные битые — возвращается ошибка с тегом ErrMalformed.
func DecodePayload(data []byte, codec Codec) (Claims, error) {
	var c Claims
	switch codec {
	case CodecJSON:
		if err := json.Unmarshal(data, &c); err != nil {
			return Claims{}, fmt.Errorf("%w: разбор payload (json): %w", ErrMalformed, err)
		}
		return c, nil
	case CodecCBOR:
		if err := cborStrict.Unmarshal(data, &c); err != nil {
			return Claims{}, fmt.Errorf("%w: разбор payload (cbor): %w", ErrMalformed, err)
		}
		return c, nil
	default:
		return Claims{}, fmt.Errorf("%w: %q", ErrUnsupportedCodec, codec)
	}
}

// cborCanonical — настройки CBOR-кодера: канонический порядок ключей и
// минимально короткие целые. Гарантируют, что одинаковые claims дают
// одинаковые байты.
var cborCanonical = mustCanonicalCBOREnc()

// cborStrict — настройки CBOR-декодера. Главное — запрет дубликатов ключей
// в map: подпись считается над сырыми байтами и подделать её через дубликаты
// нельзя, но интерпретация claims после декодирования может разойтись между
// реализациями. Строгий режим эту неоднозначность убирает.
var cborStrict = mustStrictCBORDec()

// mustCanonicalCBOREnc собирает CBOR-кодер один раз при старте пакета.
// Если что-то пошло не так — это сломанная зависимость cbor/v2, поэтому panic.
func mustCanonicalCBOREnc() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Errorf("token: построение канонического CBOR-кодера: %w", err))
	}
	return mode
}

// mustStrictCBORDec собирает CBOR-декодер один раз при старте пакета.
func mustStrictCBORDec() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(fmt.Errorf("token: построение строгого CBOR-декодера: %w", err))
	}
	return mode
}
