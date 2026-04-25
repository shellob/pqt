package jwk

import (
	"encoding/base64"
	"fmt"

	"pqt/keys"
)

// p256CoordinateSize — длина координаты точки P-256 в байтах
// (RFC 7518 §6.2.1.2).
const p256CoordinateSize = 32

// p256UncompressedPublicKeySize — длина uncompressed-представления
// публичного ключа P-256: 1 байт маркера 0x04 плюс X и Y по 32 байта.
const p256UncompressedPublicKeySize = 1 + 2*p256CoordinateSize

func ecdsaPrivateToJWK(p *keys.ECDSAPrivateKey) (JWK, error) {
	pubXY, err := p.PublicBytes()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: ec public bytes: %w", keys.ErrInvalidKey, err)
	}
	d, err := p.PrivateScalar()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: ec private bytes: %w", keys.ErrInvalidKey, err)
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
		return JWK{}, fmt.Errorf("%w: ec public bytes: %w", keys.ErrInvalidKey, err)
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
		return nil, fmt.Errorf("%w: ec curve %q (only P-256 supported)",
			keys.ErrUnsupportedAlg, j.Crv)
	}
	d, err := base64.RawURLEncoding.DecodeString(j.D)
	if err != nil {
		return nil, fmt.Errorf("%w: ec d decode: %w", keys.ErrInvalidKey, err)
	}
	if len(d) == 0 {
		return nil, fmt.Errorf("%w: ec private key missing d", keys.ErrInvalidKey)
	}
	return keys.NewECDSAPrivateFromScalar(d)
}

func parseECDSAPublicJWK(j JWK) (keys.PublicKey, error) {
	if j.Crv != "P-256" {
		return nil, fmt.Errorf("%w: ec curve %q (only P-256 supported)",
			keys.ErrUnsupportedAlg, j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: ec x decode: %w", keys.ErrInvalidKey, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: ec y decode: %w", keys.ErrInvalidKey, err)
	}
	if len(x) != p256CoordinateSize || len(y) != p256CoordinateSize {
		return nil, fmt.Errorf("%w: ec coordinates have wrong length (x=%d, y=%d)",
			keys.ErrInvalidKey, len(x), len(y))
	}
	uncompressed := make([]byte, p256UncompressedPublicKeySize)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+p256CoordinateSize], x)
	copy(uncompressed[1+p256CoordinateSize:], y)
	return keys.NewECDSAPublicFromUncompressed(uncompressed)
}
