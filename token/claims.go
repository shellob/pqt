package token

// Claims — набор утверждений токена (claims): кто его получатель, кем
// выпущен, для какой системы, до какого времени действителен и так
// далее. В JWT эти поля называются именно «claims», и большинство имён
// мы сохраняем те же — токен PQ-AT по составу полей совместим с JWT
// (RFC 7519, раздел 4.1).
//
// # Имена полей в JSON и CBOR
//
// У структуры два набора тегов сразу: json и cbor. От того, в каком
// кодеке мы сериализуем payload (см. поле Header.Enc), Go выбирает
// нужный набор:
//
//   - JSON-кодек использует json-теги: "sub", "iss", "aud" и т. д. —
//     стандартные имена из RFC 7519.
//   - CBOR-кодек использует cbor-теги вида "<число>,keyasint": ключи
//     становятся целыми числами 1..8. Это стиль CWT (CBOR Web Token,
//     RFC 8392), который заметно компактнее, потому что в CBOR
//     целое 1 занимает один байт, а строка "sub" — четыре.
//
// Соответствие чисел и полей зафиксировано в спецификации PQ-AT:
//
//	1 — sub    5 — iat
//	2 — iss    6 — jti
//	3 — aud    7 — scope
//	4 — exp    8 — kind
//
// Опция omitempty в обоих наборах тегов пропускает пустые поля при
// сериализации — за счёт этого токен короче, а пустые scope или
// необязательный kind не занимают места в payload.
//
// # Что значит каждое поле
//
//   - Sub (subject) — идентификатор того, о ком токен. Обычно это
//     ID или логин пользователя.
//   - Iss (issuer) — кто выпустил токен. URL сервера авторизации.
//   - Aud (audience) — кому токен предназначен. Идентификатор системы,
//     которая должна его принимать.
//   - Exp (expiration) — Unix-время в секундах, после которого токен
//     считается истёкшим. Обязательное поле в PQ-AT (бессрочные токены
//     запрещены).
//   - Iat (issued at) — Unix-время выпуска токена.
//   - Jti (JWT ID) — уникальный идентификатор данного конкретного
//     токена. Используется для отзыва (чёрный список) и для отслеживания
//     refresh-сессий.
//   - Scope — список прав в виде строки через пробел: «read write admin»
//     и т. п. Стандартная семантика OAuth (RFC 6749 §3.3).
//   - Kind — расширение PQ-AT поверх RFC 7519. Отличает access-токен
//     ("access") от refresh-токена ("refresh"). Если поле пустое,
//     токен считается access (для совместимости со старыми токенами,
//     выпущенными до появления Kind). Сервер авторизации использует
//     это поле, например, в /auth/refresh: туда должен прийти именно
//     refresh-токен, а не access.
type Claims struct {
	Sub   string `json:"sub,omitempty"   cbor:"1,keyasint,omitempty"`
	Iss   string `json:"iss,omitempty"   cbor:"2,keyasint,omitempty"`
	Aud   string `json:"aud,omitempty"   cbor:"3,keyasint,omitempty"`
	Exp   int64  `json:"exp,omitempty"   cbor:"4,keyasint,omitempty"`
	Iat   int64  `json:"iat,omitempty"   cbor:"5,keyasint,omitempty"`
	Jti   string `json:"jti,omitempty"   cbor:"6,keyasint,omitempty"`
	Scope string `json:"scope,omitempty" cbor:"7,keyasint,omitempty"`
	Kind  string `json:"kind,omitempty"  cbor:"8,keyasint,omitempty"`
}

// Допустимые значения поля Claims.Kind. Пустая строка эквивалентна
// KindAccess — это сделано ради совместимости со старыми токенами,
// которые выпускались до появления поля Kind вообще.
const (
	KindAccess  = "access"
	KindRefresh = "refresh"
)
