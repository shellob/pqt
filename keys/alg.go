package keys

// Alg идентифицирует алгоритм цифровой подписи токена PQ-AT.
type Alg string

// Идентификаторы алгоритмов из спецификации PQ-AT (раздел 2.2).
const (
	// AlgECDSAP256 — классическая ECDSA на кривой P-256. Используется
	// для обратной совместимости и в качестве классической компоненты
	// гибридных схем.
	AlgECDSAP256 Alg = "ecdsa-p256"

	// AlgMLDSA44 — ML-DSA уровня 2 (NIST level 2, ~AES-128). FIPS 204.
	AlgMLDSA44 Alg = "mldsa44"
	// AlgMLDSA65 — ML-DSA уровня 3 (NIST level 3, ~AES-192). FIPS 204.
	// Целевой уровень спецификации PQ-AT.
	AlgMLDSA65 Alg = "mldsa65"
	// AlgMLDSA87 — ML-DSA уровня 5 (NIST level 5, ~AES-256). FIPS 204.
	AlgMLDSA87 Alg = "mldsa87"

	// AlgHybridECDSAMLDSA44 — гибрид ECDSA P-256 и ML-DSA-44.
	AlgHybridECDSAMLDSA44 Alg = "hybrid-ecdsa-mldsa44"
	// AlgHybridECDSAMLDSA65 — гибрид ECDSA P-256 и ML-DSA-65.
	// Целевой режим спецификации PQ-AT.
	AlgHybridECDSAMLDSA65 Alg = "hybrid-ecdsa-mldsa65"
	// AlgHybridECDSAMLDSA87 — гибрид ECDSA P-256 и ML-DSA-87.
	AlgHybridECDSAMLDSA87 Alg = "hybrid-ecdsa-mldsa87"
)

// String возвращает текстовое представление алгоритма.
func (a Alg) String() string { return string(a) }

// IsHybrid возвращает true, если алгоритм является гибридным (классика + PQ).
func (a Alg) IsHybrid() bool {
	switch a {
	case AlgHybridECDSAMLDSA44, AlgHybridECDSAMLDSA65, AlgHybridECDSAMLDSA87:
		return true
	default:
		return false
	}
}

// Valid возвращает true, если Alg — известный идентификатор.
func (a Alg) Valid() bool {
	switch a {
	case AlgECDSAP256,
		AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
		AlgHybridECDSAMLDSA44, AlgHybridECDSAMLDSA65, AlgHybridECDSAMLDSA87:
		return true
	default:
		return false
	}
}
