package pqt

import (
	"time"

	"pqt/keys"
	"pqt/token"
)

// Clock возвращает «текущее» время. Validator использует его, чтобы проверять
// claim exp. В обычных вызовах достаточно time.Now; в тестах удобно подменить
// его на фиксированный момент и проверить поведение на границе.
type Clock func() time.Time

// KeySource выбирает публичный ключ для проверки подписи по заголовку токена.
//
// Реализации могут быть любыми: всегда один и тот же ключ, поиск в jwk.Set
// по полю kid, опрос внешнего JWKS-эндпоинта и т. п. Если ключ не найден —
// верните ErrKeyNotFound (или обёрнутую ошибку с этим тегом).
//
// ВАЖНО: не выбирай ключ по header.Alg. Это поле полностью контролируется
// тем, кто прислал токен; если выбрать ключ под подменённый alg, то проверка
// header.Alg против verifier.Algorithm() (которую Validate делает дальше)
// сравнит подмену с подменой и пропустит токен — это классическая атака
// alg-confusion. Правильный источник истины — header.Kid (или вообще
// фиксированный публичный ключ для статической конфигурации).
//
// Пример безопасной реализации:
//
//	func keyByKid(set jwk.Set) pqt.KeySource {
//	    return func(h token.Header) (keys.PublicKey, error) {
//	        j, ok := set.Find(h.Kid)
//	        if !ok {
//	            return nil, pqt.ErrKeyNotFound
//	        }
//	        return jwk.ParsePublic(j)
//	    }
//	}
type KeySource func(header token.Header) (keys.PublicKey, error)

// IssueOptions — параметры выпуска токена.
//
// Алгоритм в опциях не указывается специально: он берётся из Signer.Algorithm(),
// и в заголовок попадает именно он. Так невозможно случайно собрать токен,
// у которого header.alg расходится с тем, чем токен реально подписан.
type IssueOptions struct {
	// Signer — приватный ключ, которым подписывается H||P.
	Signer keys.PrivateKey

	// Codec — как кодировать payload (json или cbor). Записывается в header.enc.
	Codec token.Codec

	// Format — как собрать готовый токен (текст или бинарь).
	Format token.Format

	// Kid — идентификатор ключа, попадает в header.kid. Опционально.
	// Нужно при ротации, когда в JWKS живёт несколько ключей.
	Kid string
}

// ValidateOptions — параметры проверки токена.
type ValidateOptions struct {
	// KeySource выбирает публичный ключ по заголовку токена. Обязательное поле.
	KeySource KeySource

	// Format — формат, которым пришёл токен. Обязательное поле: validator не
	// угадывает формат по содержимому, его всегда задаёт вызывающий код по
	// контексту (HTTP Authorization: Bearer → text, gRPC metadata → binary).
	Format token.Format

	// ExpectedIssuer — если задан, claim iss токена должен с ним совпадать.
	// Пустая строка — проверка пропускается.
	ExpectedIssuer string

	// ExpectedAudience — если задан, claim aud должен с ним совпадать.
	// Пустая строка — проверка пропускается.
	ExpectedAudience string

	// Clock — источник «текущего времени» для проверки exp. Если nil,
	// используется time.Now.
	Clock Clock

	// Leeway — допустимая разница часов между issuer'ом и validator'ом.
	// Токен с exp = now - Leeway всё ещё считается валидным; полезно при
	// рассинхронизации серверных часов. Значение по умолчанию 0 — никакой
	// поблажки нет.
	Leeway time.Duration

	// IsRevoked — опциональная функция проверки, не отозван ли токен по jti.
	// Если nil — проверка пропускается. Если задана и возвращает true для
	// jti токена, Validate возвращает ErrTokenRevoked. Реализацию определяет
	// caller: чёрный список в памяти, запрос к серверу авторизации,
	// distributed cache и т. п.
	IsRevoked func(jti string) bool
}
