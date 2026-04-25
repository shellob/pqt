package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// ECDSAPrivateKey — приватный ключ ECDSA на кривой P-256. Сообщение перед
// подписью хешируется SHA-256, как требует RFC 7515 §3.4 (ES256).
type ECDSAPrivateKey struct {
	key *ecdsa.PrivateKey
}

// ECDSAPublicKey — парный публичный ключ ECDSA P-256.
type ECDSAPublicKey struct {
	key *ecdsa.PublicKey
}

// GenerateECDSA генерирует свежую пару ключей ECDSA на кривой P-256.
// Источник случайности — crypto/rand.Reader.
func GenerateECDSA() (*ECDSAPrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa generate: %w", err)
	}
	return &ECDSAPrivateKey{key: k}, nil
}

// Sign возвращает подпись в формате ASN.1 DER. Внутри сообщение сначала
// хешируется SHA-256, и подписывается уже хеш.
func (p *ECDSAPrivateKey) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa sign: %w", err)
	}
	return sig, nil
}

// Public возвращает парный публичный ключ.
func (p *ECDSAPrivateKey) Public() PublicKey {
	return &ECDSAPublicKey{key: &p.key.PublicKey}
}

// Algorithm возвращает AlgECDSAP256.
func (p *ECDSAPrivateKey) Algorithm() Alg { return AlgECDSAP256 }

// PublicBytes возвращает публичную часть в несжатом формате SEC 1
// (0x04 || X || Y, 65 байт для P-256). Нужно для сериализации в JWK.
func (p *ECDSAPrivateKey) PublicBytes() ([]byte, error) {
	return p.key.PublicKey.Bytes()
}

// PrivateScalar возвращает 32-байтовый скаляр D приватного ключа.
// Нужно для сериализации в JWK.
func (p *ECDSAPrivateKey) PrivateScalar() ([]byte, error) {
	return p.key.Bytes()
}

// Verify проверяет ASN.1 DER подпись против SHA-256 хеша сообщения.
func (v *ECDSAPublicKey) Verify(message, signature []byte) error {
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(v.key, digest[:], signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Algorithm возвращает AlgECDSAP256.
func (v *ECDSAPublicKey) Algorithm() Alg { return AlgECDSAP256 }

// Bytes возвращает публичный ключ в несжатом формате SEC 1. Нужно для
// сериализации в JWK.
func (v *ECDSAPublicKey) Bytes() ([]byte, error) {
	return v.key.Bytes()
}

// NewECDSAPublicFromUncompressed собирает публичный ключ ECDSA P-256 из
// несжатых байтов (0x04 || X || Y).
func NewECDSAPublicFromUncompressed(uncompressed []byte) (*ECDSAPublicKey, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор публичного ECDSA-ключа: %w", ErrInvalidKey, err)
	}
	return &ECDSAPublicKey{key: pub}, nil
}

// NewECDSAPrivateFromScalar собирает приватный ключ ECDSA P-256 из сырого
// 32-байтового скаляра D. Публичная часть вычисляется сама.
func NewECDSAPrivateFromScalar(scalar []byte) (*ECDSAPrivateKey, error) {
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("%w: разбор приватного ECDSA-ключа: %w", ErrInvalidKey, err)
	}
	return &ECDSAPrivateKey{key: priv}, nil
}
