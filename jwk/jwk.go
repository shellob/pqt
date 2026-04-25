package jwk

import (
	"encoding/json"
	"fmt"

	"pqt/keys"
)

// JWK — JSON Web Key для одного ключа (приватного или публичного).
//
// Поля "kid", "use", "alg" соответствуют RFC 7517. EC-специфичные X, Y, D —
// RFC 7518 §6.2. MLDSA-специфичные Pub, Priv — байтовые представления ключа
// circl, закодированные base64url. Hybrid-специфичное Components содержит
// массив из двух JWK: классическая часть, затем постквантовая.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`

	// EC (RFC 7518 §6.2)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`

	// MLDSA (расширение)
	Pub  string `json:"pub,omitempty"`
	Priv string `json:"priv,omitempty"`

	// Hybrid (расширение)
	Components []JWK `json:"components,omitempty"`
}

// String возвращает компактное JSON-представление JWK без отступов.
func (j JWK) String() string {
	b, _ := json.Marshal(j) //nolint:errchkjson // структура заведомо сериализуема
	return string(b)
}

// Sentinel-ошибка для нераспознанного "kty".
//
// Конкретные ошибки парсинга оборачивают keys.ErrInvalidKey,
// поэтому errors.Is(err, keys.ErrInvalidKey) всегда работает.
var errUnsupportedKty = fmt.Errorf("jwk: unsupported kty")

// MarshalPrivate сериализует приватный ключ в JWK. Тип ключа определяется
// его конкретным типом из пакета keys.
func MarshalPrivate(key keys.PrivateKey) (JWK, error) {
	switch k := key.(type) {
	case *keys.ECDSAPrivateKey:
		return ecdsaPrivateToJWK(k)
	case *keys.MLDSAPrivateKey:
		return mldsaPrivateToJWK(k)
	case *keys.HybridPrivateKey:
		return hybridPrivateToJWK(k)
	default:
		return JWK{}, fmt.Errorf("%w: unknown private key type %T", keys.ErrInvalidKey, key)
	}
}

// MarshalPublic сериализует публичный ключ в JWK без приватного материала.
func MarshalPublic(key keys.PublicKey) (JWK, error) {
	switch k := key.(type) {
	case *keys.ECDSAPublicKey:
		return ecdsaPublicToJWK(k)
	case *keys.MLDSAPublicKey:
		return mldsaPublicToJWK(k)
	case *keys.HybridPublicKey:
		return hybridPublicToJWK(k)
	default:
		return JWK{}, fmt.Errorf("%w: unknown public key type %T", keys.ErrInvalidKey, key)
	}
}

// ParsePrivate восстанавливает приватный ключ из JWK по полю Kty.
func ParsePrivate(j JWK) (keys.PrivateKey, error) {
	switch j.Kty {
	case "EC":
		return parseECDSAPrivateJWK(j)
	case "MLDSA":
		return parseMLDSAPrivateJWK(j)
	case "Hybrid":
		return parseHybridPrivateJWK(j)
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedKty, j.Kty)
	}
}

// ParsePublic восстанавливает публичный ключ из JWK по полю Kty.
func ParsePublic(j JWK) (keys.PublicKey, error) {
	switch j.Kty {
	case "EC":
		return parseECDSAPublicJWK(j)
	case "MLDSA":
		return parseMLDSAPublicJWK(j)
	case "Hybrid":
		return parseHybridPublicJWK(j)
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedKty, j.Kty)
	}
}
