package token

// Claims — набор утверждений токена PQ-AT, совместимый с JWT (раздел 2.2
// диссертации).
//
// В JSON используются стандартные имена полей из RFC 7519. В CBOR ключи —
// целые числа в стиле CWT (RFC 8392). Конкретное соответствие зафиксировано
// в спецификации PQ-AT (см. memory `pq_at_spec`):
//
//	1 — sub, 2 — iss, 3 — aud, 4 — exp, 5 — iat, 6 — jti, 7 — scope, 8 — kind.
//
// Опция omitempty в обоих кодеках пропускает пустые поля при сериализации —
// токен получается компактнее.
type Claims struct {
	Sub   string `json:"sub,omitempty"   cbor:"1,keyasint,omitempty"`
	Iss   string `json:"iss,omitempty"   cbor:"2,keyasint,omitempty"`
	Aud   string `json:"aud,omitempty"   cbor:"3,keyasint,omitempty"`
	Exp   int64  `json:"exp,omitempty"   cbor:"4,keyasint,omitempty"`
	Iat   int64  `json:"iat,omitempty"   cbor:"5,keyasint,omitempty"`
	Jti   string `json:"jti,omitempty"   cbor:"6,keyasint,omitempty"`
	Scope string `json:"scope,omitempty" cbor:"7,keyasint,omitempty"`

	// Kind отличает access-токен от refresh-токена. Пусто или "access" —
	// обычный токен доступа; "refresh" — токен обновления (RFC 6749 §1.5).
	// Поле — расширение PQ-AT, не входит в RFC 7519, но при отсутствии не
	// мешает совместимости.
	Kind string `json:"kind,omitempty" cbor:"8,keyasint,omitempty"`
}

// Виды токенов в поле Claims.Kind.
const (
	KindAccess  = "access"
	KindRefresh = "refresh"
)
