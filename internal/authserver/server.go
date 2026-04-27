package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"slices"
	"strings"
)

// Server — сервер авторизации PQ-AT целиком: ключи, пользователи,
// хранилища refresh-сессий и отзывов, готовый http.Handler с маршрутами.
//
// Создаётся через New один раз при старте программы. После этого его
// можно подключать к чему угодно, что принимает http.Handler — к
// http.Server в production, к httptest.NewServer в тестах. Внутреннее
// состояние (refresh-сессии, чёрный список) — потокобезопасное, так
// что сервер нормально обрабатывает параллельные запросы.
type Server struct {
	cfg     Config
	keys    *KeyStore
	users   *UserStore
	refresh *RefreshStore
	revoked *RevocationStore
	handler http.Handler
}

// New собирает Server по конфигу. Поэтапно:
//
//  1. Проверить и нормализовать конфиг (cfg.validate).
//  2. Загрузить или сгенерировать ключи (см. LoadOrInit).
//  3. Создать хранилище пользователей и захэшировать seed-пароли
//     (NewUserStore — это самая медленная часть старта при
//     production-cost=10).
//  4. Создать пустые in-memory хранилища refresh-сессий и отзывов.
//  5. Зарегистрировать маршруты HTTP.
//
// На любой шаг возможна ошибка — например, в KeysDir лежит битый JWK
// или диск некуда писать сгенерированный ключ. В таком случае New
// возвращает ошибку, и сервер не стартует.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	ks, err := LoadOrInit(cfg.KeysDir, cfg.DefaultKid, cfg.GenerateAlg)
	if err != nil {
		return nil, err
	}
	us, err := NewUserStore(cfg.BcryptCost)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:     cfg,
		keys:    ks,
		users:   us,
		refresh: NewRefreshStore(),
		revoked: NewRevocationStore(),
	}
	s.handler = s.routes()

	cfg.Logger.Info("authserver готов",
		"addr", cfg.Addr,
		"issuer", cfg.Issuer,
		"keys_dir", cfg.KeysDir,
		"default_kid", ks.defaultKid,
	)
	return s, nil
}

// Handler возвращает http.Handler сервера. Поверх него можно навесить
// дополнительный middleware (например, для CORS, логирования или
// rate-limit) и подключить к настоящему http.Server.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Issuer возвращает значение поля iss, которое сервер проставляет в
// claim iss выпускаемых токенов. Используется в основном тестами
// (проверить, что токен пришёл с ожидаемым issuer) и в документации.
func (s *Server) Issuer() string {
	return s.cfg.Issuer
}

// routes собирает таблицу HTTP-маршрутов. Используются паттерны
// http.ServeMux из Go 1.22 с явным указанием метода в начале строки
// ("POST /auth/token" вместо просто "/auth/token"). Благодаря этому
// при несоответствии метода (например, кто-то прислал GET вместо POST)
// сервер отвечает 405 Method Not Allowed автоматически, а не отдаёт
// 404 — что было бы непонятно для клиента.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/token", s.handleToken)
	mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST /auth/revoke", s.handleRevoke)
	mux.HandleFunc("GET /.well-known/pq-jwks", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleDiscovery)

	s.registerWebUI(mux)

	if s.cfg.Debug {
		registerPprof(mux)
		s.cfg.Logger.Warn("authserver: /debug/pprof включён — в боевой среде так оставлять нельзя")
	}
	return mux
}

// registerPprof вешает стандартные обработчики Go pprof на наш mux.
// pprof — встроенный профайлер: можно снять CPU-профиль, дамп кучи,
// список горутин, посмотреть мьютекс-контеншн и т. д. Очень полезен
// для главы 4.6 диссертации (нагрузочное тестирование), но в
// production-сервисе доступ к нему должен быть закрыт.
//
// Регистрируем явно, а не через скрытый импорт `_ "net/http/pprof"`,
// потому что скрытый импорт цепляет эндпоинты на глобальный
// http.DefaultServeMux безусловно — независимо от наших флагов. Тут
// мы вешаем их только при cfg.Debug, и только на наш mux.
func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// IsRevoked возвращает true, если jti есть в чёрном списке отозванных
// токенов. Метод существует именно для того, чтобы внешний
// resource-сервер мог передать его прямо в pqt.ValidateOptions.IsRevoked —
// у этих двух функций совпадает сигнатура `func(string) bool`, и
// никакой обёртки не нужно.
func (s *Server) IsRevoked(jti string) bool {
	return s.revoked.IsRevoked(jti)
}

// writeJSON сериализует value в JSON и пишет ответ с указанным
// HTTP-статусом. Ошибки сериализации логируются, но не возвращаются
// наружу: к моменту, когда мы их обнаружим, заголовки ответа уже
// отправлены клиенту и поменять статус всё равно нельзя.
func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		s.cfg.Logger.Error("authserver: запись JSON-ответа", "err", err)
	}
}

// writeOAuthError отвечает клиенту в формате ошибок OAuth 2.0
// (RFC 6749 §5.2):
//
//	{"error": "invalid_grant", "error_description": "..."}
//
// Поле error содержит код из стандартного набора (invalid_request,
// invalid_grant, unauthorized_client и т. д.). Поле error_description
// — свободный текст для логов и отладки; клиенту полагаться на
// конкретный текст не стоит.
func (s *Server) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	s.writeJSON(w, status, oauthError{Error: code, Description: description})
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// limitScope ограничивает запрошенный клиентом набор scope тем
// набором, который разрешён пользователю. Возвращает пересечение
// двух множеств в порядке, в котором клиент запросил, через пробел.
//
// Примеры:
//
//	requested="read write", allowed="read write admin" → "read write"
//	requested="read admin",  allowed="read write"        → "read"
//	requested="",            allowed="read write"        → "read write"
//
// Пустой запрос трактуется как «дай всё, что у меня есть» — это
// удобное поведение для prototype, в production-сценариях можно
// потребовать явный список.
//
// RFC 6749 §3.3 не гарантирует ни порядок, ни обязательное
// возвращение поля scope в ответе сервера, но детерминированный
// порядок очень упрощает тесты, поэтому возвращаем по порядку запроса.
func limitScope(requested, allowed string) string {
	if requested == "" {
		return allowed
	}
	allowedFields := strings.Fields(allowed)
	out := make([]string, 0, len(allowedFields))
	for _, s := range strings.Fields(requested) {
		if slices.Contains(allowedFields, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// newJTI генерирует уникальный идентификатор токена (claim jti).
// Берём 16 случайных байт из crypto/rand — это 128 бит энтропии — и
// кодируем в base64url. Этого с запасом хватает, чтобы случайная
// коллизия двух токенов была невозможна на практике (даже миллиард
// токенов в секунду в течение 100 лет дадут вероятность коллизии
// исчезающе малую).
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
