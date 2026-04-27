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

// Server — сервер авторизации PQ-AT. После создания через New его можно
// использовать как обычный http.Handler — например, через httptest.NewServer
// в тестах или http.Server в боевой среде.
type Server struct {
	cfg     Config
	keys    *KeyStore
	users   *UserStore
	refresh *RefreshStore
	revoked *RevocationStore
	handler http.Handler
}

// New собирает Server по конфигу: загружает или генерирует ключи,
// инициализирует хранилище пользователей и регистрирует маршруты.
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
// дополнительный middleware и подключить к http.Server.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Issuer возвращает значение поля iss, которое сервер проставляет в выпускаемые
// токены. Удобно для тестов и для документации.
func (s *Server) Issuer() string {
	return s.cfg.Issuer
}

// routes собирает таблицу маршрутов. Используются паттерны Go 1.22 с явным
// указанием HTTP-метода в начале — благодаря этому при несоответствии метода
// сервер отвечает 405 Method Not Allowed, а не тихо отдаёт 404.
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

// registerPprof вешает стандартные обработчики pprof из net/http/pprof на
// наш mux. Регистрируем явно, а не через скрытый импорт `_ "net/http/pprof"`:
// иначе эндпоинты pprof автоматически прицепляются к http.DefaultServeMux
// и поднимаются всегда, без проверки флага Debug.
func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// IsRevoked возвращает true, если jti есть в чёрном списке отозванных
// токенов. Метод существует именно для того, чтобы внешний resource-сервер
// мог передать его прямо в pqt.ValidateOptions.IsRevoked — у него
// совпадает сигнатура.
func (s *Server) IsRevoked(jti string) bool {
	return s.revoked.IsRevoked(jti)
}

// writeJSON сериализует value в JSON и пишет ответ с указанным статусом.
// Ошибки кодирования логируются, но не пробрасываются — заголовок к этому
// моменту уже отправлен и сделать ничего не получится.
func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		s.cfg.Logger.Error("authserver: запись JSON-ответа", "err", err)
	}
}

// writeOAuthError отвечает в формате OAuth 2.0 (RFC 6749 §5.2):
// {"error":"...", "error_description":"..."}.
func (s *Server) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	s.writeJSON(w, status, oauthError{Error: code, Description: description})
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// limitScope ограничивает запрошенный набор scope тем, что разрешено
// пользователю. Возвращает пересечение в исходном порядке, разделённое
// пробелами. RFC 6749 §3.3 не гарантирует ни порядок, ни обязательное
// возвращение поля — но детерминированный порядок упрощает тесты.
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
// 16 случайных байт в Base64url — это 128 бит энтропии, более чем достаточно,
// чтобы коллизия в практически любом масштабе была невозможна.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
