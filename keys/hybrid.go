package keys

import (
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/sync/errgroup"
)

// hybridLengthPrefixSize — количество байт префикса длины классической части
// в гибридной подписи (uint16, big-endian).
const hybridLengthPrefixSize = 2

// HybridPrivateKey — гибридная пара ключей: классический алгоритм + PQ.
// Подпись формируется как конкатенация двух подписей с префиксом длины
// классической части. Раздел 2.3 спецификации PQ-AT.
type HybridPrivateKey struct {
	classic PrivateKey
	pq      PrivateKey
	alg     Alg
}

// HybridPublicKey — соответствующий гибридный публичный ключ.
type HybridPublicKey struct {
	classic PublicKey
	pq      PublicKey
	alg     Alg
}

// NewHybrid собирает гибридную пару из классического и постквантового
// PrivateKey. Поддерживается комбинация ECDSA P-256 + ML-DSA-44/65/87.
func NewHybrid(classic, pq PrivateKey) (*HybridPrivateKey, error) {
	alg, err := combineHybridAlg(classic.Algorithm(), pq.Algorithm())
	if err != nil {
		return nil, err
	}
	return &HybridPrivateKey{classic: classic, pq: pq, alg: alg}, nil
}

// NewHybridPublic собирает гибридный публичный ключ из двух публичных ключей.
// Используется при восстановлении из JWK.
func NewHybridPublic(classic, pq PublicKey) (*HybridPublicKey, error) {
	alg, err := combineHybridAlg(classic.Algorithm(), pq.Algorithm())
	if err != nil {
		return nil, err
	}
	return &HybridPublicKey{classic: classic, pq: pq, alg: alg}, nil
}

// GenerateHybrid генерирует свежую гибридную пару с указанным уровнем PQ.
// Классическая часть всегда — ECDSA P-256.
func GenerateHybrid(pqAlg Alg) (*HybridPrivateKey, error) {
	classic, err := GenerateECDSA()
	if err != nil {
		return nil, err
	}
	pq, err := GenerateMLDSA(pqAlg)
	if err != nil {
		return nil, err
	}
	return NewHybrid(classic, pq)
}

// combineHybridAlg валидирует пару алгоритмов и возвращает идентификатор
// гибридного алгоритма.
func combineHybridAlg(classic, pq Alg) (Alg, error) {
	if classic != AlgECDSAP256 {
		return "", fmt.Errorf("%w: hybrid classic part must be %s, got %s",
			ErrAlgMismatch, AlgECDSAP256, classic)
	}
	switch pq {
	case AlgMLDSA44:
		return AlgHybridECDSAMLDSA44, nil
	case AlgMLDSA65:
		return AlgHybridECDSAMLDSA65, nil
	case AlgMLDSA87:
		return AlgHybridECDSAMLDSA87, nil
	default:
		return "", fmt.Errorf("%w: hybrid PQ part must be ML-DSA, got %s",
			ErrAlgMismatch, pq)
	}
}

// Sign подписывает сообщение последовательно: ECDSA, затем ML-DSA. Подписи
// объединяются в формате [uint16 length-of-classic][classic-sig][pq-sig].
func (p *HybridPrivateKey) Sign(message []byte) ([]byte, error) {
	classicSig, err := p.classic.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("keys: hybrid classic sign: %w", err)
	}
	pqSig, err := p.pq.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("keys: hybrid pq sign: %w", err)
	}
	return joinHybridSignature(classicSig, pqSig)
}

// Public возвращает соответствующий гибридный публичный ключ.
func (p *HybridPrivateKey) Public() PublicKey {
	return &HybridPublicKey{
		classic: p.classic.Public(),
		pq:      p.pq.Public(),
		alg:     p.alg,
	}
}

// Algorithm возвращает идентификатор гибридного алгоритма.
func (p *HybridPrivateKey) Algorithm() Alg { return p.alg }

// Components возвращает классическую и постквантовую компоненты приватного
// ключа. Используется при сериализации в JWK.
func (p *HybridPrivateKey) Components() (classic, pq PrivateKey) {
	return p.classic, p.pq
}

// Verify проверяет гибридную подпись параллельно: обе компоненты верифицируются
// одновременно через errgroup. Токен считается валидным только когда обе
// подписи корректны (конъюнкция, раздел 2.3 спецификации).
func (v *HybridPublicKey) Verify(message, signature []byte) error {
	classicSig, pqSig, err := splitHybridSignature(signature)
	if err != nil {
		return err
	}
	var eg errgroup.Group
	eg.Go(func() error {
		if err := v.classic.Verify(message, classicSig); err != nil {
			return fmt.Errorf("keys: hybrid classic verify: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		if err := v.pq.Verify(message, pqSig); err != nil {
			return fmt.Errorf("keys: hybrid pq verify: %w", err)
		}
		return nil
	})
	return eg.Wait()
}

// VerifySequential проверяет гибридную подпись последовательно. Используется
// для сравнительных бенчмарков (раздел 4.4 диссертации).
func (v *HybridPublicKey) VerifySequential(message, signature []byte) error {
	classicSig, pqSig, err := splitHybridSignature(signature)
	if err != nil {
		return err
	}
	if err := v.classic.Verify(message, classicSig); err != nil {
		return fmt.Errorf("keys: hybrid classic verify: %w", err)
	}
	if err := v.pq.Verify(message, pqSig); err != nil {
		return fmt.Errorf("keys: hybrid pq verify: %w", err)
	}
	return nil
}

// Algorithm возвращает идентификатор гибридного алгоритма.
func (v *HybridPublicKey) Algorithm() Alg { return v.alg }

// Components возвращает классическую и постквантовую компоненты публичного
// ключа. Используется при сериализации в JWK.
func (v *HybridPublicKey) Components() (classic, pq PublicKey) {
	return v.classic, v.pq
}

// joinHybridSignature собирает гибридную подпись из двух компонент.
func joinHybridSignature(classic, pq []byte) ([]byte, error) {
	if len(classic) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: classic signature too long (%d > %d)",
			ErrMalformedSignature, len(classic), math.MaxUint16)
	}
	classicLen := uint16(len(classic) & math.MaxUint16) // bounds checked above
	out := make([]byte, hybridLengthPrefixSize+len(classic)+len(pq))
	binary.BigEndian.PutUint16(out[:hybridLengthPrefixSize], classicLen)
	copy(out[hybridLengthPrefixSize:], classic)
	copy(out[hybridLengthPrefixSize+len(classic):], pq)
	return out, nil
}

// splitHybridSignature разбирает гибридную подпись на компоненты.
func splitHybridSignature(sig []byte) (classic, pq []byte, err error) {
	if len(sig) < hybridLengthPrefixSize {
		return nil, nil, fmt.Errorf("%w: signature shorter than length prefix (%d < %d)",
			ErrMalformedSignature, len(sig), hybridLengthPrefixSize)
	}
	classicLen := int(binary.BigEndian.Uint16(sig[:hybridLengthPrefixSize]))
	if classicLen == 0 {
		return nil, nil, fmt.Errorf("%w: classic signature length is zero", ErrMalformedSignature)
	}
	end := hybridLengthPrefixSize + classicLen
	if end > len(sig) {
		return nil, nil, fmt.Errorf("%w: classic length %d exceeds total signature size %d",
			ErrMalformedSignature, classicLen, len(sig))
	}
	if end == len(sig) {
		return nil, nil, fmt.Errorf("%w: pq signature missing", ErrMalformedSignature)
	}
	return sig[hybridLengthPrefixSize:end], sig[end:], nil
}
