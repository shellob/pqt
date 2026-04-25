package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// ECDSAPrivateKey — приватный ключ ECDSA на кривой P-256. Хеширование
// сообщения — SHA-256 в соответствии с RFC 7515 §3.4 (ES256).
type ECDSAPrivateKey struct {
	key *ecdsa.PrivateKey
}

// ECDSAPublicKey — соответствующий публичный ключ ECDSA P-256.
type ECDSAPublicKey struct {
	key *ecdsa.PublicKey
}

// GenerateECDSA генерирует новую пару ключей ECDSA на кривой P-256.
// Источник энтропии — crypto/rand.Reader.
func GenerateECDSA() (*ECDSAPrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa generate: %w", err)
	}
	return &ECDSAPrivateKey{key: k}, nil
}

// Sign возвращает ASN.1-DER подпись над SHA-256 хешем сообщения.
func (p *ECDSAPrivateKey) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa sign: %w", err)
	}
	return sig, nil
}

// Public возвращает соответствующий публичный ключ.
func (p *ECDSAPrivateKey) Public() PublicKey {
	return &ECDSAPublicKey{key: &p.key.PublicKey}
}

// Algorithm возвращает идентификатор AlgECDSAP256.
func (p *ECDSAPrivateKey) Algorithm() Alg { return AlgECDSAP256 }

// PublicBytes возвращает публичную часть в uncompressed-формате SEC 1
// (`0x04 || X || Y`, 65 байт для P-256). Используется при сериализации в JWK.
func (p *ECDSAPrivateKey) PublicBytes() ([]byte, error) {
	return p.key.PublicKey.Bytes()
}

// PrivateScalar возвращает 32-байтовый скаляр D приватного ключа.
// Используется при сериализации в JWK.
func (p *ECDSAPrivateKey) PrivateScalar() ([]byte, error) {
	return p.key.Bytes()
}

// Verify проверяет ASN.1-DER подпись над SHA-256 хешем сообщения.
func (v *ECDSAPublicKey) Verify(message, signature []byte) error {
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(v.key, digest[:], signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Algorithm возвращает идентификатор AlgECDSAP256.
func (v *ECDSAPublicKey) Algorithm() Alg { return AlgECDSAP256 }

// Bytes возвращает публичный ключ в uncompressed-формате SEC 1.
// Используется при сериализации в JWK.
func (v *ECDSAPublicKey) Bytes() ([]byte, error) {
	return v.key.Bytes()
}

// NewECDSAPublicFromUncompressed восстанавливает публичный ключ ECDSA P-256
// из uncompressed-представления (`0x04 || X || Y`).
func NewECDSAPublicFromUncompressed(uncompressed []byte) (*ECDSAPublicKey, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("%w: ecdsa public parse: %w", ErrInvalidKey, err)
	}
	return &ECDSAPublicKey{key: pub}, nil
}

// NewECDSAPrivateFromScalar восстанавливает приватный ключ ECDSA P-256 из
// raw-скаляра D. Публичная часть вычисляется автоматически.
func NewECDSAPrivateFromScalar(scalar []byte) (*ECDSAPrivateKey, error) {
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("%w: ecdsa private parse: %w", ErrInvalidKey, err)
	}
	return &ECDSAPrivateKey{key: priv}, nil
}
