package jwk

import (
	"fmt"

	"pqt/keys"
)

// hybridPrivateToJWK сохраняет гибридный приватный ключ в JWK. У
// гибрида внутри две независимых пары — классическая (ECDSA) и
// постквантовая (ML-DSA), и при сериализации каждая пара становится
// своим обычным JWK. Получившиеся два JWK кладутся в массив Components
// у внешнего «обёрточного» JWK с kty="Hybrid".
//
// Порядок компонентов фиксированный: первым всегда идёт классическая
// половина, вторым — постквантовая. На разборе мы полагаемся на этот
// порядок, поэтому никогда нельзя класть их в обратном.
//
// Реализация рекурсивная: обе половины пропускаются через ту же
// функцию MarshalPrivate, которой пользуется внешний код, — то есть
// нам не нужно дублировать код сериализации EC и ML-DSA.
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

// hybridPublicToJWK — то же для публичного гибридного ключа. Каждая
// половина превращается в публичный JWK без приватного материала
// (D или Priv остаются пустыми).
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

// parseHybridPrivateJWK собирает приватный гибрид обратно из JWK.
// Шаги: проверить, что в Components ровно два элемента; разобрать
// первый как классический приватный ключ, второй — как постквантовый;
// собрать гибрид через keys.NewHybrid.
//
// Если элементов не два — это структурная ошибка JWK: гибридная
// подпись по определению из двух половин, ни одной больше, ни одной
// меньше.
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

// parseHybridPublicJWK — то же для публичного гибридного ключа.
// Используется на стороне валидатора при разборе JWKS-набора:
// пришёл JWK с kty="Hybrid", собираем из него keys.HybridPublicKey
// и передаём в Validate как verifier.
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
