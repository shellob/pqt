package keys

// PrivateKey подписывает произвольные сообщения и предоставляет парный
// PublicKey для верификации.
//
// Реализации: ECDSAPrivateKey, MLDSAPrivateKey, HybridPrivateKey.
// Конструкторы (GenerateECDSA, GenerateMLDSA, NewHybrid, GenerateHybrid)
// возвращают конкретные типы; аргументы функций принимают этот интерфейс.
type PrivateKey interface {
	// Sign возвращает подпись сообщения. Формат подписи зависит от алгоритма:
	//
	//   ecdsa-p256              — ASN.1 DER, ~70–72 байта.
	//   mldsa44/65/87           — фиксированный размер по FIPS 204.
	//   hybrid-ecdsa-mldsa<n>   — uint16 длины ECDSA в big-endian, далее
	//                             байты ECDSA-подписи, далее байты ML-DSA.
	Sign(message []byte) (signature []byte, err error)

	// Public возвращает соответствующий публичный ключ.
	Public() PublicKey

	// Algorithm возвращает идентификатор алгоритма ключа.
	Algorithm() Alg
}

// PublicKey проверяет подписи, созданные парным PrivateKey.
type PublicKey interface {
	// Verify возвращает nil при валидной подписи, ErrInvalidSignature
	// при невалидной, и обёрнутую ошибку при структурных проблемах.
	Verify(message, signature []byte) error

	// Algorithm возвращает идентификатор алгоритма ключа.
	Algorithm() Alg
}
