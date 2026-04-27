package token

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// EncodePayload сериализует Claims в байты через выбранный кодек —
// JSON или CBOR.
//
// Для CodecCBOR используется так называемый канонический режим из
// библиотеки fxamacker/cbor (CanonicalEncOptions). «Канонический» здесь
// значит две вещи: ключи в map'ах раскладываются всегда в одном и том
// же фиксированном порядке, и целые числа пишутся в минимально возможном
// числе байт (например, 0 — один байт, не четыре). Благодаря этому
// одни и те же claims всегда дают одинаковую байтовую последовательность.
//
// Зачем это важно. Подпись считается над байтами заголовка и payload.
// Если бы CBOR-кодер однажды выдал поля в одном порядке, а в другой
// раз в другом — получились бы разные байты, а значит подпись была бы
// разной для тех же самых claims. Канонический режим эту нестабильность
// исключает.
//
// У нас в Claims нет float-полей, поэтому формально точное соответствие
// «детерминированному кодированию» из RFC 8949 §4.2.1 — отдельный
// разговор; в нашей задаче канонического режима достаточно.
//
// Для CodecJSON используется стандартный encoding/json. Он сериализует
// поля структуры в порядке их объявления, так что вывод тоже стабилен
// без дополнительных настроек.
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

// DecodePayload разбирает байты payload обратно в Claims, выбирая кодек
// по тому же значению, под которым его записали (см. поле Header.Enc).
//
// Для CodecCBOR используется строгий режим декодера: если в payload
// встречается map, в которой один и тот же ключ повторяется (например,
// дважды поле "sub"), декодер вернёт ошибку, а не молча выберет одно из
// значений. Это закрытие класса проблем, связанных с дубликатами:
// подпись в нашей системе считается над сырыми байтами и через
// дубликаты её не подделать, но разные библиотеки CBOR-разборщиков
// могут по-разному интерпретировать «который из двух» — кто-то берёт
// первый, кто-то последний. Если на одном сервисе пройдёт «sub=alice»,
// а на другом «sub=evil» из тех же байт, это уязвимость. Строгий режим
// просто запрещает такие payload-ы.
//
// Любая ошибка разбора (битые байты, дубликат, неизвестный кодек)
// возвращается с тегом ErrMalformed.
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

// cborCanonical — настройки CBOR-кодера, собранные один раз при старте
// пакета. Канонический порядок ключей + минимально короткие целые;
// эти параметры гарантируют, что одни и те же claims всегда дают
// одинаковую байтовую последовательность. Подробности — в комментарии
// к EncodePayload.
var cborCanonical = mustCanonicalCBOREnc()

// cborStrict — настройки CBOR-декодера, собранные один раз при старте
// пакета. Главное в них — DupMapKeyEnforcedAPF: при встрече дубликата
// ключа в map декодер не пытается ничего «выбрать», а возвращает
// ошибку. Подробности — в комментарии к DecodePayload.
var cborStrict = mustStrictCBORDec()

// mustCanonicalCBOREnc собирает CBOR-кодер на этапе инициализации
// пакета. Если по какой-то причине это не удалось (битая зависимость
// cbor/v2), пакет в принципе работать не будет — поэтому panic
// здесь оправдан: лучше упасть сразу при старте программы, чем
// поймать ошибку при первом же выпуске токена в production.
func mustCanonicalCBOREnc() cbor.EncMode {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Errorf("token: построение канонического CBOR-кодера: %w", err))
	}
	return mode
}

// mustStrictCBORDec — то же самое для CBOR-декодера.
func mustStrictCBORDec() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(fmt.Errorf("token: построение строгого CBOR-декодера: %w", err))
	}
	return mode
}
