package jwk

import (
	"encoding/json"
	"fmt"

	"pqt/keys"
)

// JWK — структура одного ключа в формате JSON Web Key. Используется и
// для приватных, и для публичных ключей; разница в том, какие поля
// заполнены.
//
// Поля можно поделить на три группы:
//
//  1. Общие (RFC 7517) — указывают, какой это ключ и для чего:
//     Kty (key type, обязательный), Alg (алгоритм), Use (назначение —
//     "sig" для подписи, "enc" для шифрования), Kid (идентификатор
//     ключа).
//
//  2. Поля для EC-ключей (RFC 7518 §6.2) — Crv (curve, у нас всегда
//     "P-256"), X и Y (координаты точки на кривой, в base64url),
//     D (приватный скаляр, есть только в приватном ключе).
//
//  3. Наши расширения для постквантовой подписи: Pub и Priv для
//     ML-DSA (байты ключа в base64url), Components для гибрида
//     (массив из двух JWK — классическая половина и постквантовая).
//
// Все поля кроме Kty — с omitempty: то есть в JSON-выводе они
// появляются только если действительно заполнены. Поэтому одна и та
// же структура нормально описывает и EC-ключ (заполнены X/Y/D), и
// ML-DSA-ключ (заполнены Pub/Priv), и гибрид (заполнено Components),
// без лишних null-значений в выводе.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`

	// EC (RFC 7518 §6.2): координаты X и Y для публичной части,
	// скаляр D для приватной. Все три — base64url.
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`

	// ML-DSA (наше расширение): публичный и приватный ключи в виде
	// сырых байтов из circl, закодированных в base64url. Длины зависят
	// от уровня (см. keys.AlgMLDSA44/65/87).
	Pub  string `json:"pub,omitempty"`
	Priv string `json:"priv,omitempty"`

	// Гибрид (наше расширение): массив из двух JWK. Первый элемент —
	// классическая половина (kty=EC), второй — постквантовая (kty=MLDSA).
	Components []JWK `json:"components,omitempty"`
}

// String возвращает JWK как компактную JSON-строку без отступов.
// Удобно для логов и для отладки. В норме структура заведомо
// сериализуется без ошибок (все поля — базовые типы Go), поэтому
// ошибку json.Marshal здесь можно безопасно игнорировать.
func (j JWK) String() string {
	b, _ := json.Marshal(j) //nolint:errchkjson // структура заведомо сериализуема
	return string(b)
}

// errUnsupportedKty — маркерная ошибка для случая, когда в JWK указан
// неизвестный тип ключа (поле kty). Например, "RSA" — мы такие не
// поддерживаем, отказываем.
//
// Все остальные ошибки разбора JWK (битые поля, не та длина, не та
// кривая) возвращаются с тегом keys.ErrInvalidKey, чтобы вызывающий
// код через errors.Is(err, keys.ErrInvalidKey) одинаково ловил
// «что-то с ключом не так» вне зависимости от деталей.
var errUnsupportedKty = fmt.Errorf("jwk: unsupported kty")

// MarshalPrivate превращает приватный ключ в JWK. Какие именно поля
// заполняются, зависит от конкретного типа ключа: EC заполняет
// X/Y/D + Crv, ML-DSA заполняет Pub/Priv, гибрид собирает Components
// из двух вложенных JWK.
//
// Конкретный тип определяется через type switch — поэтому keys
// специально экспортирует *ECDSAPrivateKey, *MLDSAPrivateKey и
// *HybridPrivateKey, а не только интерфейс PrivateKey.
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

// MarshalPublic — то же самое, но для публичного ключа. Никаких
// приватных полей (D, Priv) в результат не попадает. Это самый
// частый сценарий: серверу нужно опубликовать свои публичные ключи
// в JWKS, чтобы клиенты могли проверять подписи.
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

// ParsePrivate делает обратное MarshalPrivate: получает JWK и
// возвращает живой Go-объект приватного ключа. Какой именно тип ключа
// собрать, понимается из поля kty.
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

// ParsePublic — обратное к MarshalPublic. Используется на стороне
// проверки токена: получили JWKS, нашли в нём JWK по нужному kid,
// собрали из него публичный ключ, передали в Validate.
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
