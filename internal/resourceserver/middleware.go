package resourceserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"pqt"
	"pqt/token"
)

// claimsCtxKey — ключ, под которым middleware кладёт claims в контекст
// HTTP-запроса. Тип-обёртка нужна, чтобы случайно не столкнуться с такими
// же ключами из других пакетов (стандартная Go-идиома для context.Value).
type claimsCtxKey struct{}

// ClaimsFromContext достаёт claims, которые middleware RequireValidToken
// положил в контекст обработчика. Возвращает (claims, false), если в
// контексте их нет — например, если обработчик вызвали в обход middleware.
func ClaimsFromContext(ctx context.Context) (token.Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(token.Claims)
	return c, ok
}

// withClaims возвращает производный контекст с положенными claims внутри.
// Функция сделана приватной — пишет в контекст только middleware, чтобы
// нельзя было «подкрутить» claims из обычного обработчика мимо проверки.
func withClaims(parent context.Context, c token.Claims) context.Context {
	return context.WithValue(parent, claimsCtxKey{}, c)
}

// Middleware — стандартная Go-сигнатура для http-middleware: функция,
// которая принимает следующий обработчик и возвращает обёртку над ним.
type Middleware func(http.Handler) http.Handler

// RequireValidToken возвращает middleware, который пропускает запрос дальше
// только при наличии валидного PQ-AT-токена в заголовке Authorization.
// Проверка делается через pqt.Validate с переданными опциями (KeySource,
// ExpectedIssuer, ExpectedAudience и т. д.).
//
// При успехе claims извлечённого токена кладутся в контекст запроса —
// обработчик получает их через ClaimsFromContext. На любую ошибку
// (нет заголовка, неверный формат, неправильная подпись, истёкший exp,
// отозванный токен) middleware возвращает 401 с JSON-телом по RFC 6750 §3.1.
func RequireValidToken(opts pqt.ValidateOptions) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				writeUnauthorized(w, "invalid_request", err.Error())
				return
			}

			claims, err := pqt.Validate([]byte(tokenStr), opts)
			if err != nil {
				// По RFC 6750 §3.1 коды разделяются так:
				//   invalid_request — сам HTTP-запрос построен неправильно
				//                     (нет заголовка Authorization);
				//   invalid_token   — токен есть, но он невалиден по любой
				//                     причине: просрочен, подделан, отозван,
				//                     не разобрался.
				// Любая ошибка от pqt.Validate относится ко второй категории.
				writeUnauthorized(w, "invalid_token", err.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
		})
	}
}

// RequireScope возвращает middleware, пропускающий запрос дальше только
// если в claim scope текущего токена присутствует нужное значение. Этот
// middleware всегда вешается ПОСЛЕ RequireValidToken: без него в контексте
// нет claims, и проверять было бы нечего.
func RequireScope(scope string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// Это не «пользователь не авторизовался», а «разработчик
				// неправильно собрал цепочку middleware»: RequireValidToken
				// должен стоять впереди. Возвращаем 500, чтобы такая
				// проблема была сразу заметна в логах, а не маскировалась
				// под 401 «вы не авторизованы».
				writeError(w, http.StatusInternalServerError, "server_error",
					"claims отсутствуют в контексте — поставьте RequireValidToken перед RequireScope")
				return
			}
			if !hasScope(claims.Scope, scope) {
				writeError(w, http.StatusForbidden, "insufficient_scope",
					"требуется scope: "+scope)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken достаёт сам токен из заголовка вида
// `Authorization: Bearer <token>`. Слово Bearer сравниваем
// регистронезависимо — этого требует RFC 6750 §2.1.
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("отсутствует заголовок Authorization")
	}
	const prefix = "bearer "
	lowered := strings.ToLower(header)
	if !strings.HasPrefix(lowered, prefix) {
		return "", errors.New("заголовок Authorization не Bearer")
	}
	tok := strings.TrimSpace(header[len(prefix):])
	if tok == "" {
		return "", errors.New("заголовок Authorization без токена")
	}
	return tok, nil
}

// hasScope проверяет, есть ли в строке scope (записи через пробел)
// нужное значение want.
func hasScope(scope, want string) bool {
	if scope == "" || want == "" {
		return false
	}
	return slices.Contains(strings.Fields(scope), want)
}

// errorBody — формат тела ошибки от middleware. Поля совпадают с теми,
// что использует OAuth, — клиенту проще писать общий разбор.
type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeUnauthorized(w http.ResponseWriter, code, description string) {
	// RFC 6750 §3 рекомендует возвращать заголовок WWW-Authenticate с
	// challenge-строкой, но её правильное составление с экранированием —
	// нетривиально. Для прототипа диссертации хватает JSON-тела.
	writeError(w, http.StatusUnauthorized, code, description)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, ErrorDescription: description})
}
