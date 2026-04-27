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

// claimsCtxKey — ключ, под которым middleware кладёт claims в context.Context
// HTTP-запроса. Сделан отдельным неэкспортируемым типом, потому что это
// стандартная идиома Go для ключей в context.Value: если бы здесь стояла
// просто строка "claims", любой другой пакет мог бы случайно записать
// своё значение под таким же ключом и затереть наше. Тип-обёртка с
// уникальным именем такие коллизии исключает.
type claimsCtxKey struct{}

// ClaimsFromContext достаёт claims, которые middleware RequireValidToken
// положил в контекст обработчика. Возвращает (claims, false), если в
// контексте их нет — например, если обработчик вызвали в обход middleware.
func ClaimsFromContext(ctx context.Context) (token.Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(token.Claims)
	return c, ok
}

// withClaims возвращает новый контекст, в который дописаны claims. Сама
// функция намеренно неэкспортируемая: класть claims в контекст имеет
// право только проверяющий middleware, после успешной валидации токена.
// Если бы функция была публичной, обычный обработчик мог бы записать
// произвольные claims в контекст в обход проверки и притвориться
// аутентифицированным.
func withClaims(parent context.Context, c token.Claims) context.Context {
	return context.WithValue(parent, claimsCtxKey{}, c)
}

// Middleware — общепринятая в Go форма обёртки HTTP-обработчика: функция
// принимает следующий обработчик и возвращает новый, который что-то делает
// до или после вызова исходного. Такие обёртки удобно складывать в цепочки —
// сначала RequireValidToken, потом RequireScope, потом сам бизнес-обработчик.
type Middleware func(http.Handler) http.Handler

// RequireValidToken — основной middleware защиты эндпоинтов. Берёт токен
// из заголовка Authorization: Bearer <token>, валидирует его через
// pqt.Validate с переданными опциями (источник ключей, ожидаемый издатель,
// ожидаемая аудитория, проверка отзыва, leeway часов и т. д.) и кладёт
// разобранные claims в контекст запроса. Дальше обработчик читает их
// через ClaimsFromContext.
//
// При любой проблеме — заголовка нет, формат не «Bearer …», подпись
// не сходится, exp в прошлом, токен в чёрном списке, kid не найден —
// возвращается ответ 401 с JSON-телом по RFC 6750 §3.1: поля error и
// error_description, которые клиенту легко разобрать однообразно.
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
				// RFC 6750 §3.1 различает два кода ошибки в ответе 401:
				//   invalid_request — сломан сам HTTP-запрос (например,
				//                     не пришёл заголовок Authorization);
				//   invalid_token   — заголовок есть, но содержимое токена
				//                     не подходит: просрочен, подпись не
				//                     сходится, токен отозван, не разобрался.
				// Всё, что вернула pqt.Validate, относится ко второй
				// категории — заголовок мы уже успешно прочитали выше.
				writeUnauthorized(w, "invalid_token", err.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
		})
	}
}

// RequireScope — middleware на следующий уровень после RequireValidToken.
// scope — это claim из токена, перечисляющий через пробел права, которые
// auth-сервер выдал клиенту: например "read write admin". RequireScope
// проверяет, что нужное право в этом списке действительно есть, иначе
// возвращает 403 insufficient_scope.
//
// Этот middleware обязан стоять в цепочке ПОСЛЕ RequireValidToken: claims
// в контекст кладёт именно RequireValidToken, без него RequireScope
// просто нечего читать. Если так получилось (ошибка сборки цепочки) —
// возвращается 500, чтобы её сразу было заметно (см. ниже).
func RequireScope(scope string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// Это не «пользователь не авторизовался», а «разработчик
				// собрал цепочку middleware в неправильном порядке»:
				// RequireValidToken должен стоять впереди RequireScope.
				// Возвращаем 500, чтобы такая ошибка конфигурации сразу
				// светилась в логах сервера, а не маскировалась под
				// обычный 401 «вы не авторизованы» (его пользователь
				// мог бы списать на просроченный токен).
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

// extractBearerToken достаёт строку токена из заголовка
// `Authorization: Bearer <token>`. Само слово "Bearer" в стандарте
// признаётся в любом регистре (RFC 6750 §2.1: "Authentication scheme names
// are case-insensitive"), поэтому сравниваем по нижнему регистру.
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

// hasScope проверяет, есть ли в claim scope (формат RFC 6749 §3.3 — список
// слов через пробел, например "read write admin") нужное значение want.
// Если scope пустой или want пустой — считаем, что нужного права нет.
func hasScope(scope, want string) bool {
	if scope == "" || want == "" {
		return false
	}
	return slices.Contains(strings.Fields(scope), want)
}

// errorBody — формат тела ошибки, который middleware возвращает клиенту.
// Поля error и error_description — те же самые, что использует OAuth для
// сообщений об ошибках на /auth/token: клиент может писать один разборщик
// и для auth-сервера, и для resource-сервера.
type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeUnauthorized(w http.ResponseWriter, code, description string) {
	// RFC 6750 §3 рекомендует к 401-ответу добавлять заголовок
	// WWW-Authenticate с подробной challenge-строкой (в духе
	// Bearer realm="…", error="invalid_token"). Корректное составление этой
	// строки с экранированием спецсимволов — отдельная задача. Для прототипа
	// диссертации этого нет: клиенту хватает кода и описания в JSON-теле.
	writeError(w, http.StatusUnauthorized, code, description)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, ErrorDescription: description})
}
