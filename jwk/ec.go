package jwk

import (
	"encoding/base64"
	"fmt"

	"pqt/keys"
)

// p256CoordinateSize — длина одной координаты точки P-256 в байтах
// (RFC 7518 §6.2.1.2).
const p256CoordinateSize = 32

// p256UncompressedPublicKeySize — полная длина публичного ключа P-256
// в несжатом формате: маркер 0x04 + X (32 байта) + Y (32 байта).
const p256UncompressedPublicKeySize = 1 + 2*p256CoordinateSize

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
