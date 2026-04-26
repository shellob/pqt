package resourceserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"pqt"
	"pqt/keys"
	"pqt/token"
)

// Server — resource-сервер. Создаётся через New, дальше используется как
// обычный http.Handler.
type Server struct {
	cfg     Config
	jwks    *JWKSClient
	handler http.Handler
}

// New собирает Server по конфигу. Сразу же делает первичный fetch JWKS
// с auth-сервера, чтобы при первом запросе уже не было сетевой задержки.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if _, err := url.Parse(cfg.AuthServerBaseURL); err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	jwksClient := NewJWKSClient(cfg.AuthServerBaseURL, httpClient, cfg.Logger)

	if err := jwksClient.Refresh(context.Background()); err != nil {
		// Стартуем даже если auth-сервер недоступен: при первом валидном
		// запросе JWKSClient попробует ещё раз. Логируем как warning.
		cfg.Logger.Warn("resourceserver: первичная загрузка JWKS не удалась — попробуем на лету",
			"err", err)
	}

	s := &Server{
		cfg:  cfg,
		jwks: jwksClient,
	}
	s.handler = s.routes()

	cfg.Logger.Info("resourceserver готов",
		"addr", cfg.Addr,
		"auth_server", cfg.AuthServerBaseURL,
		"expected_issuer", cfg.ExpectedIssuer,
	)
	return s, nil
}

// Handler возвращает http.Handler сервера для подключения к http.Server.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// JWKS возвращает внутренний JWKS-клиент. Полезно для интеграционных тестов
// и для дополнительных middleware, которым нужен резолвер ключей.
func (s *Server) JWKS() *JWKSClient {
	return s.jwks
}

// validateOptions собирает pqt.ValidateOptions из конфига сервера.
// Выделено отдельным методом, чтобы тесты могли подменить только KeySource
// (например, на функцию, которая всегда возвращает ключ из памяти).
func (s *Server) validateOptions() pqt.ValidateOptions {
	return pqt.ValidateOptions{
		KeySource: func(h token.Header) (keys.PublicKey, error) {
			return s.jwks.KeyByKid(h)
		},
		Format:           token.FormatText,
		ExpectedIssuer:   s.cfg.ExpectedIssuer,
		ExpectedAudience: s.cfg.ExpectedAudience,
		Leeway:           s.cfg.Leeway,
		Clock:            s.cfg.Now,
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	authn := RequireValidToken(s.validateOptions())
	requireAdmin := RequireScope("admin")

	mux.Handle("GET /me", authn(http.HandlerFunc(s.handleMe)))
	mux.Handle("GET /admin", authn(requireAdmin(http.HandlerFunc(s.handleAdmin))))
	return mux
}

// handleMe возвращает claims из контекста — это самый простой способ
// показать клиенту «кто я с точки зрения этого сервиса».
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "server_error",
			"claims отсутствуют в контексте")
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// handleAdmin — демо-эндпоинт «только для админов». Если до сюда долетел
// запрос — middleware уже убедился, что в scope есть admin.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "доступ разрешён",
		"sub":     claims.Sub,
		"scope":   claims.Scope,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
