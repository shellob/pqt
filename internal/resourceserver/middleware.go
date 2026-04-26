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

// claimsCtxKey — ключ для хранения claims в request context. Тип-обёртка
// нужна, чтобы исключить случайные коллизии с другими пакетами.
type claimsCtxKey struct{}

// ClaimsFromContext извлекает claims, которые middleware RequireValidToken
// положил в контекст. Возвращает (claims, false), если контекст без них —
// например, обработчик вызван минуя middleware.
func ClaimsFromContext(ctx context.Context) (token.Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(token.Claims)
	return c, ok
}

// withClaims возвращает производный контекст с положенными внутрь claims.
// Скрыт от внешнего мира — пишет в контекст только middleware.
func withClaims(parent context.Context, c token.Claims) context.Context {
	return context.WithValue(parent, claimsCtxKey{}, c)
}

// Middleware — стандартная Go-сигнатура для http-middleware.
type Middleware func(http.Handler) http.Handler

// RequireValidToken возвращает middleware, который пропускает запрос дальше
// только если в заголовке Authorization лежит валидный токен PQ-AT,
// проверенный через pqt.Validate с переданными опциями.
//
// Извлечённые claims помещаются в контекст и доступны обработчику через
// ClaimsFromContext. На любую ошибку (нет заголовка, кривой формат,
// невалидная подпись, истёкший exp, отозван) возвращается 401 с телом
// в формате RFC 6750 §3.1 (через JSON).
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
				// По RFC 6750 §3.1: "invalid_token" — токен невалиден по
				// любой причине (просрочен, подделан, отозван, не разобрался).
				// "invalid_request" мы используем только когда сам HTTP-запрос
				// сформирован неправильно (нет заголовка Authorization).
				writeUnauthorized(w, "invalid_token", err.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
		})
	}
}

// RequireScope возвращает middleware, который пускает дальше только запросы
// с claim scope, содержащим заданное значение. Используется поверх
// RequireValidToken — отдельно от него этот middleware смысла не имеет:
// без RequireValidToken claims в контексте не будет.
func RequireScope(scope string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// Это не «пользователь не авторизовался», а «разработчик
				// неправильно собрал цепочку middleware» — RequireValidToken
				// должен стоять впереди. Возвращаем 500, чтобы такое было
				// видно в логах, а не маскировалось под 401.
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

// extractBearerToken достаёт токен из заголовка Authorization: Bearer <token>.
// Регистронезависимо к слову Bearer (RFC 6750 §2.1).
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

// hasScope проверяет, что в строке scope (через пробелы) присутствует want.
func hasScope(scope, want string) bool {
	if scope == "" || want == "" {
		return false
	}
	return slices.Contains(strings.Fields(scope), want)
}

// errorBody — формат ответа на ошибки middleware. Совпадает по полям с
// OAuth-ошибкой, чтобы клиенту было меньше кода для разбора.
type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeUnauthorized(w http.ResponseWriter, code, description string) {
	// RFC 6750 §3 рекомендует WWW-Authenticate, но он же вынуждает строить
	// challenge-строку с экранированием — для прототипа достаточно JSON-тела.
	writeError(w, http.StatusUnauthorized, code, description)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, ErrorDescription: description})
}
