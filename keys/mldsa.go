package keys

import (
	"encoding"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// MLDSAPrivateKey оборачивает приватный ключ ML-DSA через унифицированный
// интерфейс sign.Scheme из cloudflare/circl. Уровень безопасности (44/65/87)
// определяется полем alg.
type MLDSAPrivateKey struct {
	scheme sign.Scheme
	sk     sign.PrivateKey
	alg    Alg
}

// MLDSAPublicKey — соответствующий публичный ключ ML-DSA.
type MLDSAPublicKey struct {
	scheme sign.Scheme
	pk     sign.PublicKey
	alg    Alg
}

// GenerateMLDSA генерирует пару ключей ML-DSA указанного уровня.
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

// Sign возвращает ML-DSA-подпись фиксированного размера для выбранного уровня.
// Контекст и pre-hashed-режимы спецификацией PQ-AT не используются.
func (p *MLDSAPrivateKey) Sign(message []byte) ([]byte, error) {
	return p.scheme.Sign(p.sk, message, nil), nil
}

// Public возвращает парный публичный ключ. Извлекается из приватного через
// sign.PrivateKey.Public(); это операция без копирования секретного материала.
func (p *MLDSAPrivateKey) Public() PublicKey {
	return &MLDSAPublicKey{
		scheme: p.scheme,
		pk:     p.sk.Public().(sign.PublicKey),
		alg:    p.alg,
	}
}

// Algorithm возвращает уровень ML-DSA, заданный при генерации ключа.
func (p *MLDSAPrivateKey) Algorithm() Alg { return p.alg }

// PrivateBytes возвращает байтовое представление приватного ключа в формате
// circl. Длина зависит от уровня (FIPS 204).
func (p *MLDSAPrivateKey) PrivateBytes() ([]byte, error) {
	return marshalCirclBinary(p.sk)
}

// PublicBytes возвращает байтовое представление публичной части.
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

// Algorithm возвращает уровень ML-DSA публичного ключа.
func (v *MLDSAPublicKey) Algorithm() Alg { return v.alg }

// Bytes возвращает байтовое представление публичного ключа в формате circl.
func (v *MLDSAPublicKey) Bytes() ([]byte, error) {
	return marshalCirclBinary(v.pk)
}

// NewMLDSAPrivateFromBytes восстанавливает приватный ключ ML-DSA указанного
// уровня из байтового представления circl.
func NewMLDSAPrivateFromBytes(alg Alg, data []byte) (*MLDSAPrivateKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	sk, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: mldsa private parse: %w", ErrInvalidKey, err)
	}
	return &MLDSAPrivateKey{scheme: scheme, sk: sk, alg: alg}, nil
}

// NewMLDSAPublicFromBytes восстанавливает публичный ключ ML-DSA указанного
// уровня из байтового представления circl.
func NewMLDSAPublicFromBytes(alg Alg, data []byte) (*MLDSAPublicKey, error) {
	scheme, err := mldsaScheme(alg)
	if err != nil {
		return nil, err
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: mldsa public parse: %w", ErrInvalidKey, err)
	}
	return &MLDSAPublicKey{scheme: scheme, pk: pk, alg: alg}, nil
}

// mldsaScheme сопоставляет наш Alg внутреннему имени circl.
// Имена ML-DSA-44/65/87 фиксированы в реестре schemes.ByName().
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
		return nil, fmt.Errorf("%w: scheme %q not found in circl registry",
			ErrUnsupportedAlg, name)
	}
	return scheme, nil
}

// marshalCirclBinary сериализует ключ circl, который должен реализовывать
// encoding.BinaryMarshaler (это контракт sign.PrivateKey/PublicKey).
func marshalCirclBinary(key any) ([]byte, error) {
	m, ok := key.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("%w: key %T does not implement BinaryMarshaler",
			ErrInvalidKey, key)
	}
	b, err := m.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %w", ErrInvalidKey, err)
	}
	return b, nil
}

// Используется только для проверки во время компиляции, что sign.PublicKey
// и sign.PrivateKey действительно поддерживают BinaryMarshaler в текущей
// версии circl.
var (
	_ encoding.BinaryMarshaler = (sign.PublicKey)(nil)
	_ encoding.BinaryMarshaler = (sign.PrivateKey)(nil)
)
