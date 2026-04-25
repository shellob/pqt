package jwk

import (
	"encoding/base64"
	"fmt"

	"pqt/keys"
)

func mldsaPrivateToJWK(p *keys.MLDSAPrivateKey) (JWK, error) {
	priv, err := p.PrivateBytes()
	if err != nil {
		return JWK{}, err
	}
	pub, err := p.PublicBytes()
	if err != nil {
		return JWK{}, err
	}
	return JWK{
		Kty:  "MLDSA",
		Alg:  string(p.Algorithm()),
		Pub:  base64.RawURLEncoding.EncodeToString(pub),
		Priv: base64.RawURLEncoding.EncodeToString(priv),
	}, nil
}

func mldsaPublicToJWK(v *keys.MLDSAPublicKey) (JWK, error) {
	pub, err := v.Bytes()
	if err != nil {
		return JWK{}, err
	}
	return JWK{
		Kty: "MLDSA",
		Alg: string(v.Algorithm()),
		Pub: base64.RawURLEncoding.EncodeToString(pub),
	}, nil
}

func parseMLDSAPrivateJWK(j JWK) (keys.PrivateKey, error) {
	priv, err := base64.RawURLEncoding.DecodeString(j.Priv)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор поля priv: %w", keys.ErrInvalidKey, err)
	}
	if len(priv) == 0 {
		return nil, fmt.Errorf("%w: у приватного ML-DSA-ключа нет поля priv", keys.ErrInvalidKey)
	}
	return keys.NewMLDSAPrivateFromBytes(keys.Alg(j.Alg), priv)
}

func parseMLDSAPublicJWK(j JWK) (keys.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(j.Pub)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор поля pub: %w", keys.ErrInvalidKey, err)
	}
	if len(pub) == 0 {
		return nil, fmt.Errorf("%w: у публичного ML-DSA-ключа нет поля pub", keys.ErrInvalidKey)
	}
	return keys.NewMLDSAPublicFromBytes(keys.Alg(j.Alg), pub)
}
