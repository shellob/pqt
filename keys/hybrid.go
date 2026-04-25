package keys

import (
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/sync/errgroup"
)

// hybridLengthPrefixSize — сколько байт отведено под длину классической части
// в гибридной подписи (uint16, big-endian).
const hybridLengthPrefixSize = 2

// HybridPrivateKey — гибридная пара ключей: классический алгоритм + постквантовый.
// Подпись получается склейкой двух подписей с длиной классической части
// в начале (раздел 2.3 спецификации PQ-AT).
type HybridPrivateKey struct {
	classic PrivateKey
	pq      PrivateKey
	alg     Alg
}

// HybridPublicKey — парный гибридный публичный ключ.
type HybridPublicKey struct {
	classic PublicKey
	pq      PublicKey
	alg     Alg
}

// NewHybrid собирает гибридную пару из готовых классического и постквантового
// ключей. Допустимая комбинация одна — ECDSA P-256 + ML-DSA-44/65/87.
func NewHybrid(classic, pq PrivateKey) (*HybridPrivateKey, error) {
	alg, err := combineHybridAlg(classic.Algorithm(), pq.Algorithm())
	if err != nil {
		return nil, err
	}
	return &HybridPrivateKey{classic: classic, pq: pq, alg: alg}, nil
}

// NewHybridPublic собирает гибридный публичный ключ из двух публичных ключей.
// Используется, когда ключ восстанавливается из JWK.
func NewHybridPublic(classic, pq PublicKey) (*HybridPublicKey, error) {
	alg, err := combineHybridAlg(classic.Algorithm(), pq.Algorithm())
	if err != nil {
		return nil, err
	}
	return &HybridPublicKey{classic: classic, pq: pq, alg: alg}, nil
}

// GenerateHybrid генерирует свежую гибридную пару с заданным уровнем ML-DSA.
// Классическая половина всегда — ECDSA P-256.
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

// combineHybridAlg проверяет, что пара алгоритмов разрешённая, и возвращает
// идентификатор соответствующего гибридного алгоритма.
func combineHybridAlg(classic, pq Alg) (Alg, error) {
	if classic != AlgECDSAP256 {
		return "", fmt.Errorf("%w: классическая часть гибрида должна быть %s, получено %s",
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
		return "", fmt.Errorf("%w: постквантовая часть гибрида должна быть ML-DSA, получено %s",
			ErrAlgMismatch, pq)
	}
}

// Sign подписывает сообщение по очереди — сначала ECDSA, потом ML-DSA — и
// склеивает обе подписи в формате [2 байта длины classic][classic][pq].
func (p *HybridPrivateKey) Sign(message []byte) ([]byte, error) {
	classicSig, err := p.classic.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("keys: гибрид, классическая подпись: %w", err)
	}
	pqSig, err := p.pq.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("keys: гибрид, PQ-подпись: %w", err)
	}
	return joinHybridSignature(classicSig, pqSig)
}

// Public возвращает парный гибридный публичный ключ.
func (p *HybridPrivateKey) Public() PublicKey {
	return &HybridPublicKey{
		classic: p.classic.Public(),
		pq:      p.pq.Public(),
		alg:     p.alg,
	}
}

// Algorithm возвращает идентификатор гибридного алгоритма.
func (p *HybridPrivateKey) Algorithm() Alg { return p.alg }

// Components возвращает классическую и постквантовую половины приватного
// ключа. Нужно для сериализации в JWK.
func (p *HybridPrivateKey) Components() (classic, pq PrivateKey) {
	return p.classic, p.pq
}

// Verify проверяет гибридную подпись параллельно: обе половины сверяются
// одновременно через errgroup. Токен считается валидным, только если обе
// подписи правильные (раздел 2.3 спецификации, конъюнкция).
func (v *HybridPublicKey) Verify(message, signature []byte) error {
	classicSig, pqSig, err := splitHybridSignature(signature)
	if err != nil {
		return err
	}
	var eg errgroup.Group
	eg.Go(func() error {
		if err := v.classic.Verify(message, classicSig); err != nil {
			return fmt.Errorf("keys: гибрид, проверка классической подписи: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		if err := v.pq.Verify(message, pqSig); err != nil {
			return fmt.Errorf("keys: гибрид, проверка PQ-подписи: %w", err)
		}
		return nil
	})
	return eg.Wait()
}

// VerifySequential проверяет гибридную подпись последовательно: сначала
// классическая половина, потом постквантовая. Нужно для бенчмарков из
// раздела 4.4 диссертации, где сравнивается выигрыш от параллельной проверки.
func (v *HybridPublicKey) VerifySequential(message, signature []byte) error {
	classicSig, pqSig, err := splitHybridSignature(signature)
	if err != nil {
		return err
	}
	if err := v.classic.Verify(message, classicSig); err != nil {
		return fmt.Errorf("keys: гибрид, проверка классической подписи: %w", err)
	}
	if err := v.pq.Verify(message, pqSig); err != nil {
		return fmt.Errorf("keys: гибрид, проверка PQ-подписи: %w", err)
	}
	return nil
}

// Algorithm возвращает идентификатор гибридного алгоритма.
func (v *HybridPublicKey) Algorithm() Alg { return v.alg }

// Components возвращает классическую и постквантовую половины публичного
// ключа. Нужно для сериализации в JWK.
func (v *HybridPublicKey) Components() (classic, pq PublicKey) {
	return v.classic, v.pq
}

// joinHybridSignature склеивает классическую и постквантовую подписи в одну
// гибридную: сначала 2 байта длины классической части, потом сама классическая
// подпись, потом постквантовая.
func joinHybridSignature(classic, pq []byte) ([]byte, error) {
	if len(classic) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: классическая подпись слишком длинная (%d > %d)",
			ErrMalformedSignature, len(classic), math.MaxUint16)
	}
	classicLen := uint16(len(classic) & math.MaxUint16) // длина проверена выше
	out := make([]byte, hybridLengthPrefixSize+len(classic)+len(pq))
	binary.BigEndian.PutUint16(out[:hybridLengthPrefixSize], classicLen)
	copy(out[hybridLengthPrefixSize:], classic)
	copy(out[hybridLengthPrefixSize+len(classic):], pq)
	return out, nil
}

// splitHybridSignature разбирает гибридную подпись обратно на две половины.
func splitHybridSignature(sig []byte) (classic, pq []byte, err error) {
	if len(sig) < hybridLengthPrefixSize {
		return nil, nil, fmt.Errorf("%w: подпись короче префикса длины (%d < %d)",
			ErrMalformedSignature, len(sig), hybridLengthPrefixSize)
	}
	classicLen := int(binary.BigEndian.Uint16(sig[:hybridLengthPrefixSize]))
	if classicLen == 0 {
		return nil, nil, fmt.Errorf("%w: длина классической подписи равна нулю", ErrMalformedSignature)
	}
	end := hybridLengthPrefixSize + classicLen
	if end > len(sig) {
		return nil, nil, fmt.Errorf("%w: длина классической подписи %d больше всей подписи (%d байт)",
			ErrMalformedSignature, classicLen, len(sig))
	}
	if end == len(sig) {
		return nil, nil, fmt.Errorf("%w: PQ-подпись отсутствует", ErrMalformedSignature)
	}
	return sig[hybridLengthPrefixSize:end], sig[end:], nil
}
