package keys

// PrivateKey умеет подписывать произвольные байты и отдавать парный PublicKey
// для проверки этих подписей.
//
// Реализации: ECDSAPrivateKey, MLDSAPrivateKey, HybridPrivateKey.
// Конструкторы (GenerateECDSA, GenerateMLDSA, NewHybrid, GenerateHybrid)
// возвращают конкретный тип; функции, которые берут ключ на вход, принимают
// этот интерфейс.
type PrivateKey interface {
	// Sign возвращает подпись сообщения. Что именно лежит в этих байтах —
	// зависит от алгоритма:
	//
	//   ecdsa-p256              — ASN.1 DER, около 70–72 байт.
	//   mldsa44/65/87           — фиксированный размер по FIPS 204.
	//   hybrid-ecdsa-mldsa<n>   — сначала 2 байта длины ECDSA (big-endian),
	//                             потом сама ECDSA-подпись, потом ML-DSA.
	Sign(message []byte) (signature []byte, err error)

	// Public возвращает парный публичный ключ.
	Public() PublicKey

	// Algorithm возвращает идентификатор алгоритма этого ключа.
	Algorithm() Alg
}

// PublicKey проверяет подписи, сделанные парным PrivateKey.
type PublicKey interface {
	// Verify возвращает nil, если подпись правильная. Если подпись неверна —
	// ErrInvalidSignature. Если что-то структурно не сходится (например,
	// гибридная подпись битая) — ошибка с тегом ErrMalformedSignature
	// или ErrInvalidKey.
	Verify(message, signature []byte) error

	// Algorithm возвращает идентификатор алгоритма этого ключа.
	Algorithm() Alg
}
