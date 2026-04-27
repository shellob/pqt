package jwk

import (
	"encoding/base64"
	"fmt"

	"pqt/keys"
)

// mldsaPrivateToJWK кладёт приватный ML-DSA-ключ в JWK. У ML-DSA нет
// «координат» в духе ECDSA — внутри библиотеки circl ключ хранится
// как один сплошной блок байтов фиксированной длины (длина зависит
// от уровня — см. keys/mldsa.go). Поэтому в JWK мы используем простые
// поля Pub и Priv с base64url-байтами этих блоков. Это наше
// расширение формата (RFC 7517 такого kty не описывает).
//
// В поле Alg попадает один из mldsa44/65/67 — по нему при разборе
// мы поймём, какой длины ждать байты ключа.
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

// mldsaPublicToJWK — то же для публичного ключа: только поле Pub,
// поле Priv остаётся пустым.
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

// parseMLDSAPrivateJWK собирает приватный ML-DSA-ключ из JWK. Берёт
// поле Priv, декодирует из base64url, передаёт в конструктор пакета
// keys вместе с алгоритмом из поля Alg (он определяет уровень — 44,
// 65 или 87, и значит ожидаемую длину байт).
//
// Проверка len(priv) == 0 ловит распространённую ошибку: вместо
// приватного JWK пытаются скормить публичный (там Priv не заполнен).
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

// parseMLDSAPublicJWK — то же для публичного ключа: декодирует поле
// Pub, передаёт в keys.NewMLDSAPublicFromBytes. Это самый частый
// сценарий на стороне валидатора — публичные ключи приходят из JWKS,
// и из них нужно собрать живой ключ для проверки подписи.
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
