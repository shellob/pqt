package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// ECDSAPrivateKey — приватный ключ ECDSA (Elliptic Curve Digital Signature
// Algorithm) на кривой P-256. Это та же самая подпись, которую JWT
// использует под именем ES256.
//
// Внутри хранит указатель на стандартный *ecdsa.PrivateKey из пакета
// crypto/ecdsa. Своих собственных параметров не добавляет — наша
// обёртка нужна только чтобы выровнять API с интерфейсами PrivateKey /
// PublicKey, которые единые для всех реализаций.
//
// Сообщение перед подписью хешируется SHA-256. Так требует RFC 7515 §3.4
// (раздел про алгоритм ES256): подписывается не само сообщение, а его
// 32-байтовый SHA-256-хеш. На скорость подписи длина сообщения почти
// не влияет — основное время уходит на математику над эллиптической
// кривой.
type ECDSAPrivateKey struct {
	key *ecdsa.PrivateKey
}

// ECDSAPublicKey — парный публичный ключ. Содержит точку (X, Y) на
// кривой P-256, по которой можно проверить подпись, но нельзя её сделать.
type ECDSAPublicKey struct {
	key *ecdsa.PublicKey
}

// GenerateECDSA создаёт новую пару ключей: вытягивает случайный скаляр
// (приватный ключ) из криптографического источника случайности
// crypto/rand.Reader и вычисляет от него точку на кривой (публичный ключ).
//
// Возвращает только приватный ключ, потому что из него методом Public()
// в любой момент можно получить парный публичный — это дешёвая операция.
func GenerateECDSA() (*ECDSAPrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa generate: %w", err)
	}
	return &ECDSAPrivateKey{key: k}, nil
}

// Sign возвращает подпись в формате ASN.1 DER. Это бинарный формат
// записи структуры из двух больших целых чисел (r, s), которые и
// составляют ECDSA-подпись. Длина выходных байт — около 70-72 байта,
// варьируется на 1-2 байта в зависимости от того, помещаются ли r и s
// в свои буферы целиком или нужен дополнительный нулевой байт.
//
// Внутри: считается SHA-256-хеш сообщения, и подписывается уже он.
// Источник случайности (для генерации одноразового скаляра подписи) —
// crypto/rand.Reader.
func (p *ECDSAPrivateKey) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa sign: %w", err)
	}
	return sig, nil
}

// Public возвращает парный публичный ключ. Это просто обёртка вокруг
// поля PublicKey стандартной структуры; ничего тяжёлого не считается.
func (p *ECDSAPrivateKey) Public() PublicKey {
	return &ECDSAPublicKey{key: &p.key.PublicKey}
}

// Algorithm возвращает идентификатор AlgECDSAP256, под которым этот
// ключ известен в формате PQ-AT.
func (p *ECDSAPrivateKey) Algorithm() Alg { return AlgECDSAP256 }

// PublicBytes возвращает публичную часть в несжатом формате SEC 1.
// SEC 1 — это стандарт от SECG, описывающий способ записать точку на
// эллиптической кривой в виде байтов. Несжатый формат имеет вид:
//
//	0x04 || X || Y
//
// Один байт-маркер 0x04 (означает «несжатая запись») + 32 байта
// X-координаты + 32 байта Y-координаты, всего 65 байт для P-256.
//
// Нужно при сериализации ключа в JWK (JSON Web Key) — там X и Y
// лежат отдельными полями x и y, и мы достаём их из этого блока.
func (p *ECDSAPrivateKey) PublicBytes() ([]byte, error) {
	return p.key.PublicKey.Bytes()
}

// PrivateScalar возвращает приватную часть в виде сырого 32-байтового
// скаляра D. Это то самое случайное число, из которого получены X и Y
// публичного ключа; зная D, можно подписать что угодно от лица этого
// ключа, поэтому хранить и пересылать его нужно так же бережно, как
// и любой другой секрет.
//
// Используется при сериализации в JWK (поле d).
func (p *ECDSAPrivateKey) PrivateScalar() ([]byte, error) {
	return p.key.Bytes()
}

// Verify проверяет, что переданная подпись (в ASN.1 DER) действительно
// сделана для данного сообщения парным приватным ключом.
//
// Реализация: сначала считается SHA-256-хеш сообщения (точно так же,
// как при подписи), потом стандартный ecdsa.VerifyASN1 сверяет хеш
// с подписью. Если что-то не сходится — возвращаем ErrInvalidSignature
// без подробностей: знать, на каком именно этапе сорвалось, для
// безопасности не нужно.
func (v *ECDSAPublicKey) Verify(message, signature []byte) error {
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(v.key, digest[:], signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Algorithm возвращает AlgECDSAP256.
func (v *ECDSAPublicKey) Algorithm() Alg { return AlgECDSAP256 }

// Bytes возвращает публичный ключ в несжатом формате SEC 1
// (см. описание у ECDSAPrivateKey.PublicBytes).
func (v *ECDSAPublicKey) Bytes() ([]byte, error) {
	return v.key.Bytes()
}

// NewECDSAPublicFromUncompressed собирает публичный ключ из его
// несжатого SEC 1-представления (0x04 || X || Y). Стандартный
// crypto/ecdsa проверяет, что точка действительно лежит на кривой
// P-256; если нет — возвращается ошибка с тегом ErrInvalidKey.
//
// Используется, когда мы получили публичный ключ извне — например,
// прочитали JWK с полями x и y, склеили обратно в несжатый формат и
// хотим получить «живой» Go-объект.
func NewECDSAPublicFromUncompressed(uncompressed []byte) (*ECDSAPublicKey, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор публичного ECDSA-ключа: %w", ErrInvalidKey, err)
	}
	return &ECDSAPublicKey{key: pub}, nil
}

// NewECDSAPrivateFromScalar собирает приватный ключ из сырого 32-байтового
// скаляра D. Публичная часть (X, Y) вычисляется автоматически — это
// произведение скаляра D на базовую точку кривой; операция дешёвая.
//
// Используется при загрузке ключа из JWK (поле d).
func NewECDSAPrivateFromScalar(scalar []byte) (*ECDSAPrivateKey, error) {
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор приватного ECDSA-ключа: %w", ErrInvalidKey, err)
	}
	return &ECDSAPrivateKey{key: priv}, nil
}
