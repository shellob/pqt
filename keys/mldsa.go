package keys

import (
	"encoding"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// MLDSAPrivateKey оборачивает приватный ключ ML-DSA из библиотеки
// cloudflare/circl. Уровень безопасности (44, 65 или 87) задаётся полем alg.
type MLDSAPrivateKey struct {
	scheme sign.Scheme
	sk     sign.PrivateKey
	alg    Alg
}

// MLDSAPublicKey — парный публичный ключ ML-DSA.
type MLDSAPublicKey struct {
	scheme sign.Scheme
	pk     sign.PublicKey
	alg    Alg
}

// GenerateMLDSA генерирует пару ключей ML-DSA нужного уровня.
// Допустимые значения: AlgMLDSA44, AlgMLDSA65, AlgMLDSA87.
func GenerateMLDSA(alg Alg) (*MLDSAPrivateKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	_, sk, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("keys: mldsa generate: %w", err)
	}
	return &MLDSAPrivateKey{scheme: scheme, sk: sk, alg: alg}, nil
}

// Sign возвращает ML-DSA-подпись фиксированного для уровня размера.
// Контекст и pre-hashed-режим в спецификации PQ-AT не используются.
func (p *MLDSAPrivateKey) Sign(message []byte) ([]byte, error) {
	return p.scheme.Sign(p.sk, message, nil), nil
}

// Public возвращает парный публичный ключ. Достаётся из приватного через
// sign.PrivateKey.Public(); секретный материал при этом не копируется.
func (p *MLDSAPrivateKey) Public() PublicKey {
	return &MLDSAPublicKey{
		scheme: p.scheme,
		pk:     p.sk.Public().(sign.PublicKey),
		alg:    p.alg,
	}
}

// Algorithm возвращает уровень ML-DSA, который был выбран при генерации ключа.
func (p *MLDSAPrivateKey) Algorithm() Alg { return p.alg }

// PrivateBytes возвращает приватный ключ в байтовом виде, как его сериализует
// circl. Длина зависит от уровня (FIPS 204).
func (p *MLDSAPrivateKey) PrivateBytes() ([]byte, error) {
	return marshalCirclBinary(p.sk)
}

// PublicBytes возвращает публичную часть в байтовом виде circl.
func (p *MLDSAPrivateKey) PublicBytes() ([]byte, error) {
	return marshalCirclBinary(p.sk.Public())
}

// Verify проверяет ML-DSA-подпись.
func (v *MLDSAPublicKey) Verify(message, signature []byte) error {
	if !v.scheme.Verify(v.pk, message, signature, nil) {
		return ErrInvalidSignature
	}
	return nil
}

// Algorithm возвращает уровень ML-DSA этого публичного ключа.
func (v *MLDSAPublicKey) Algorithm() Alg { return v.alg }

// Bytes возвращает публичный ключ в байтовом виде circl.
func (v *MLDSAPublicKey) Bytes() ([]byte, error) {
	return marshalCirclBinary(v.pk)
}

// NewMLDSAPrivateFromBytes собирает приватный ML-DSA-ключ нужного уровня
// из байтов в формате circl.
func NewMLDSAPrivateFromBytes(alg Alg, data []byte) (*MLDSAPrivateKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	sk, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор приватного ML-DSA-ключа: %w", ErrInvalidKey, err)
	}
	return &MLDSAPrivateKey{scheme: scheme, sk: sk, alg: alg}, nil
}

// NewMLDSAPublicFromBytes собирает публичный ML-DSA-ключ нужного уровня
// из байтов в формате circl.
func NewMLDSAPublicFromBytes(alg Alg, data []byte) (*MLDSAPublicKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор публичного ML-DSA-ключа: %w", ErrInvalidKey, err)
	}
	return &MLDSAPublicKey{scheme: scheme, pk: pk, alg: alg}, nil
}

// mldsaScheme переводит наш Alg в имя схемы из circl. Имена ML-DSA-44/65/87
// прописаны в реестре schemes.ByName().
func mldsaScheme(alg Alg) (sign.Scheme, error) {
	var name string
	switch alg {
	case AlgMLDSA44:
		name = "ML-DSA-44"
	case AlgMLDSA65:
		name = "ML-DSA-65"
	case AlgMLDSA87:
		name = "ML-DSA-87"
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
	scheme := schemes.ByName(name)
	if scheme == nil {
		return nil, fmt.Errorf("%w: схема %q не найдена в реестре circl",
			ErrUnsupportedAlg, name)
	}
	return scheme, nil
}

// marshalCirclBinary сериализует ключ из circl в байты. Контракт circl
// гарантирует, что sign.PrivateKey и sign.PublicKey реализуют
// encoding.BinaryMarshaler — но на всякий случай проверяем это явно.
func marshalCirclBinary(key any) ([]byte, error) {
	m, ok := key.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("%w: ключ %T не реализует BinaryMarshaler",
			ErrInvalidKey, key)
	}
	b, err := m.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: сериализация ключа: %w", ErrInvalidKey, err)
	}
	return b, nil
}

// Проверка во время компиляции, что в текущей версии circl интерфейсы
// sign.PrivateKey и sign.PublicKey действительно поддерживают BinaryMarshaler.
// Если кто-то обновит circl и эта проверка перестанет компилироваться — это
// сразу станет видно.
var (
	_ encoding.BinaryMarshaler = (sign.PublicKey)(nil)
	_ encoding.BinaryMarshaler = (sign.PrivateKey)(nil)
)
