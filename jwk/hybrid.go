package jwk

import (
	"fmt"

	"pqt/keys"
)

func hybridPrivateToJWK(p *keys.HybridPrivateKey) (JWK, error) {
	classicKey, pqKey := p.Components()
	classic, err := MarshalPrivate(classicKey)
	if err != nil {
		return JWK{}, fmt.Errorf("гибрид, классическая часть: %w", err)
	}
	pq, err := MarshalPrivate(pqKey)
	if err != nil {
		return JWK{}, fmt.Errorf("гибрид, PQ-часть: %w", err)
	}
	return JWK{
		Kty:        "Hybrid",
		Alg:        string(p.Algorithm()),
		Components: []JWK{classic, pq},
	}, nil
}

func hybridPublicToJWK(v *keys.HybridPublicKey) (JWK, error) {
	classicKey, pqKey := v.Components()
	classic, err := MarshalPublic(classicKey)
	if err != nil {
		return JWK{}, fmt.Errorf("гибрид, классическая часть: %w", err)
	}
	pq, err := MarshalPublic(pqKey)
	if err != nil {
		return JWK{}, fmt.Errorf("гибрид, PQ-часть: %w", err)
	}
	return JWK{
		Kty:        "Hybrid",
		Alg:        string(v.Algorithm()),
		Components: []JWK{classic, pq},
	}, nil
}

func parseHybridPrivateJWK(j JWK) (keys.PrivateKey, error) {
	if len(j.Components) != 2 {
		return nil, fmt.Errorf("%w: у гибрида ожидаем ровно 2 компонента, получено %d",
			keys.ErrInvalidKey, len(j.Components))
	}
	classic, err := ParsePrivate(j.Components[0])
	if err != nil {
		return nil, fmt.Errorf("гибрид, классическая часть: %w", err)
	}
	pq, err := ParsePrivate(j.Components[1])
	if err != nil {
		return nil, fmt.Errorf("гибрид, PQ-часть: %w", err)
	}
	return keys.NewHybrid(classic, pq)
}

func parseHybridPublicJWK(j JWK) (keys.PublicKey, error) {
	if len(j.Components) != 2 {
		return nil, fmt.Errorf("%w: у гибрида ожидаем ровно 2 компонента, получено %d",
			keys.ErrInvalidKey, len(j.Components))
	}
	classic, err := ParsePublic(j.Components[0])
	if err != nil {
		return nil, fmt.Errorf("гибрид, классическая часть: %w", err)
	}
	pq, err := ParsePublic(j.Components[1])
	if err != nil {
		return nil, fmt.Errorf("гибрид, PQ-часть: %w", err)
	}
	return keys.NewHybridPublic(classic, pq)
}
