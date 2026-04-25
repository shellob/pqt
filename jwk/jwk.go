package jwk

import (
	"encoding/json"
	"fmt"

	"pqt/keys"
)

// JWK — JSON Web Key для одного ключа: приватного или публичного.
//
// Поля Kid, Use, Alg — общие для всех типов ключей (RFC 7517).
// Поля Crv, X, Y, D относятся к EC-ключам (RFC 7518 §6.2).
// Поля Pub, Priv — байтовое представление ML-DSA-ключа (формат circl,
// закодированный в Base64url). Это наше расширение.
// Поле Components — для гибридного ключа: массив из двух JWK,
// сначала классическая часть, потом постквантовая. Тоже расширение.
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

	// ML-DSA (наше расширение)
	Pub  string `json:"pub,omitempty"`
	Priv string `json:"priv,omitempty"`

	// Гибрид (наше расширение)
	Components []JWK `json:"components,omitempty"`
}

// String возвращает JWK как компактную JSON-строку без отступов.
func (j JWK) String() string {
	b, _ := json.Marshal(j) //nolint:errchkjson // структура заведомо сериализуема
	return string(b)
}

// errUnsupportedKty — маркерная ошибка, когда поле kty в JWK неизвестное.
//
// Все остальные ошибки разбора JWK возвращаются с тегом keys.ErrInvalidKey,
// поэтому errors.Is(err, keys.ErrInvalidKey) на стороне вызывающего работает
// в любом случае.
var errUnsupportedKty = fmt.Errorf("jwk: unsupported kty")

// MarshalPrivate сериализует приватный ключ в JWK. Какой именно ключ — решается
// по конкретному типу из пакета keys.
func MarshalPrivate(key keys.PrivateKey) (JWK, error) {
	switch k := key.(type) {
	case *keys.ECDSAPrivateKey:
		return ecdsaPrivateToJWK(k)
	case *keys.MLDSAPrivateKey:
		return mldsaPrivateToJWK(k)
	case *keys.HybridPrivateKey:
		return hybridPrivateToJWK(k)
	default:
		return JWK{}, fmt.Errorf("%w: неизвестный тип приватного ключа %T", keys.ErrInvalidKey, key)
	}
}

// MarshalPublic сериализует публичный ключ в JWK. Приватный материал в JWK,
// конечно, не попадает.
func MarshalPublic(key keys.PublicKey) (JWK, error) {
	switch k := key.(type) {
	case *keys.ECDSAPublicKey:
		return ecdsaPublicToJWK(k)
	case *keys.MLDSAPublicKey:
		return mldsaPublicToJWK(k)
	case *keys.HybridPublicKey:
		return hybridPublicToJWK(k)
	default:
		return JWK{}, fmt.Errorf("%w: неизвестный тип публичного ключа %T", keys.ErrInvalidKey, key)
	}
}

// ParsePrivate собирает приватный ключ из JWK. Какой именно — определяется
// полем kty.
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

// ParsePublic собирает публичный ключ из JWK. Какой именно — определяется
// полем kty.
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
