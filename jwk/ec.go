package jwk

import (
	"encoding/base64"
	"fmt"

	"pqt/keys"
)

// p256CoordinateSize — длина одной координаты точки на кривой P-256
// в байтах. По стандарту (RFC 7518 §6.2.1.2) каждая из координат X и Y
// — это 256-битное число, то есть 32 байта.
const p256CoordinateSize = 32

// p256UncompressedPublicKeySize — длина публичного ключа P-256 в
// несжатом виде SEC 1: один байт-маркер 0x04 (означает «несжатая
// запись точки»), потом 32 байта X-координаты, потом 32 байта
// Y-координаты, всего 65 байт.
const p256UncompressedPublicKeySize = 1 + 2*p256CoordinateSize

// ecdsaPrivateToJWK кладёт приватный ECDSA-ключ в структуру JWK.
// Заполняются три поля специфичных для эллиптической кривой:
//
//   - Crv = "P-256" — какая именно кривая используется;
//   - X, Y — координаты публичной точки, отдельно в base64url;
//   - D — приватный скаляр в base64url.
//
// Поля X, Y, D достаются из ключа в виде сырых байтов и кодируются в
// base64url. Несжатые байты публичного ключа пакета keys выглядят как
// 0x04 || X || Y (см. SEC 1), поэтому первый байт мы пропускаем,
// следующие 32 — это X, последние 32 — Y.
func ecdsaPrivateToJWK(p *keys.ECDSAPrivateKey) (JWK, error) {
	pubXY, err := p.PublicBytes()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: байты публичного EC-ключа: %w", keys.ErrInvalidKey, err)
	}
	d, err := p.PrivateScalar()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: байты приватного EC-ключа: %w", keys.ErrInvalidKey, err)
	}
	return JWK{
		Kty: "EC",
		Alg: string(keys.AlgECDSAP256),
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubXY[1 : 1+p256CoordinateSize]),
		Y:   base64.RawURLEncoding.EncodeToString(pubXY[1+p256CoordinateSize:]),
		D:   base64.RawURLEncoding.EncodeToString(d),
	}, nil
}

// ecdsaPublicToJWK — то же самое для публичного ключа: заполняются
// X и Y, поле D остаётся пустым (в публичном ключе приватного скаляра
// нет по определению).
func ecdsaPublicToJWK(v *keys.ECDSAPublicKey) (JWK, error) {
	pubXY, err := v.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: байты публичного EC-ключа: %w", keys.ErrInvalidKey, err)
	}
	return JWK{
		Kty: "EC",
		Alg: string(keys.AlgECDSAP256),
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pubXY[1 : 1+p256CoordinateSize]),
		Y:   base64.RawURLEncoding.EncodeToString(pubXY[1+p256CoordinateSize:]),
	}, nil
}

// parseECDSAPrivateJWK собирает приватный ключ обратно из JWK. Берёт
// поле D, декодирует его из base64url в сырые 32 байта и передаёт в
// конструктор keys.NewECDSAPrivateFromScalar (он сам вычислит X и Y).
//
// Дополнительные проверки:
//   - Crv должен быть "P-256". Других кривых мы не поддерживаем,
//     потому что на уровне keys у нас только AlgECDSAP256.
//   - D должен быть непустой строкой. Без приватного скаляра ключ
//     не приватный, и собирать тут нечего.
func parseECDSAPrivateJWK(j JWK) (keys.PrivateKey, error) {
	if j.Crv != "P-256" {
		return nil, fmt.Errorf("%w: кривая EC %q (поддерживаем только P-256)",
			keys.ErrUnsupportedAlg, j.Crv)
	}
	d, err := base64.RawURLEncoding.DecodeString(j.D)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор d: %w", keys.ErrInvalidKey, err)
	}
	if len(d) == 0 {
		return nil, fmt.Errorf("%w: у приватного EC-ключа нет поля d", keys.ErrInvalidKey)
	}
	return keys.NewECDSAPrivateFromScalar(d)
}

// parseECDSAPublicJWK собирает публичный ключ из JWK. Складывает X и Y
// обратно в байты несжатого SEC 1-представления (0x04 || X || Y) и
// передаёт в конструктор пакета keys.
//
// Проверка длины каждой координаты — обязательная защита от испорченного
// JWK: если по какой-то причине X или Y получились не 32 байта, точка
// либо не лежит на кривой, либо лежит на ней случайно с неправильными
// координатами; в любом случае это битый ключ.
func parseECDSAPublicJWK(j JWK) (keys.PublicKey, error) {
	if j.Crv != "P-256" {
		return nil, fmt.Errorf("%w: кривая EC %q (поддерживаем только P-256)",
			keys.ErrUnsupportedAlg, j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор x: %w", keys.ErrInvalidKey, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор y: %w", keys.ErrInvalidKey, err)
	}
	if len(x) != p256CoordinateSize || len(y) != p256CoordinateSize {
		return nil, fmt.Errorf("%w: координаты EC неправильной длины (x=%d, y=%d)",
			keys.ErrInvalidKey, len(x), len(y))
	}
	uncompressed := make([]byte, p256UncompressedPublicKeySize)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+p256CoordinateSize], x)
	copy(uncompressed[1+p256CoordinateSize:], y)
	return keys.NewECDSAPublicFromUncompressed(uncompressed)
}
