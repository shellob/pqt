package token

// Format говорит, как склеить три части токена (header, payload, подпись)
// в один поток байт. На сами части он не влияет — только на способ упаковки
// и передачи.
type Format string

const (
	// FormatText — JWT-совместимый текст: Base64url(H).Base64url(P).Base64url(Sig).
	// Подходит для HTTP-заголовка Authorization: Bearer.
	FormatText Format = "text"

	// FormatBinary — компактный бинарный формат:
	// [2 байта длины H] H [2 байта длины P] P [подпись].
	// Без накладных расходов Base64url, удобен для gRPC, WebSocket
	// и других бинарных каналов.
	FormatBinary Format = "binary"
)

// String возвращает строковое имя формата.
func (f Format) String() string { return string(f) }

// Valid возвращает true, если f — один из известных форматов.
func (f Format) Valid() bool {
	switch f {
	case FormatText, FormatBinary:
		return true
	default:
		return false
	}
}
