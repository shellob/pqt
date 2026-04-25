package token

// Codec говорит, как сериализовать payload токена. Значение хранится в поле
// Header.Enc; при выпуске токена Issuer кодирует payload именно этим способом,
// а Validator потом таким же способом его разбирает.
type Codec string

const (
	// CodecJSON — обычный JSON (RFC 8259) со строковыми именами полей.
	// Совместим с JWT и удобен для отладки глазами.
	CodecJSON Codec = "json"

	// CodecCBOR — бинарный CBOR (RFC 8949) с целочисленными ключами в стиле
	// CWT (RFC 8392). По размеру выигрывает у JSON примерно 40–50% на типовом
	// наборе claims.
	CodecCBOR Codec = "cbor"
)

// String возвращает строковое имя кодека.
func (c Codec) String() string { return string(c) }

// Valid возвращает true, если c — один из известных кодеков.
func (c Codec) Valid() bool {
	switch c {
	case CodecJSON, CodecCBOR:
		return true
	default:
		return false
	}
}
