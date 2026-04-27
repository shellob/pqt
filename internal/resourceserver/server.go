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

// Server — собранный resource-сервер. Поля внутри неэкспортируемые: всё
// взаимодействие снаружи идёт через метод Handler (даёт http.Handler для
// http.Server) и JWKS (доступ к клиенту JWKS, полезно в тестах).
type Server struct {
	cfg     Config
	jwks    *JWKSClient
	handler http.Handler
}

// New собирает Server по конфигу: проверяет/нормализует поля, поднимает
// клиент JWKS и регистрирует маршруты.
//
// На старте сервер сразу пробует скачать JWKS с auth-сервера. Это нужно,
// чтобы первый же входящий запрос не ждал пока сервер сходит за ключами по
// сети — пользователь почувствует разницу. Если auth-сервер сейчас
// недоступен, мы всё равно стартуем: JWKSClient умеет дёрнуть JWKS на
// лету при первом cache-miss, так что ситуация починится сама. В лог
// уходит предупреждение, чтобы было видно — что-то не так.
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

// Handler возвращает готовый http.Handler сервера. В main достаточно
// передать его в http.Server{Handler: srv.Handler()}.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// JWKS возвращает внутренний клиент JWKS. Нужно интеграционным тестам,
// чтобы вручную дёрнуть Refresh и убедиться, что ключи перекачались, а
// также дополнительным middleware, которым нужен тот же резолвер ключей,
// что использует основной обработчик.
func (s *Server) JWKS() *JWKSClient {
	return s.jwks
}

// validateOptions собирает набор настроек для pqt.Validate из конфига
// сервера. Вынесено в отдельный метод, чтобы тесты могли подменить только
// KeySource — например, на функцию, которая возвращает ключ прямо из
// памяти, минуя JWKS-клиент и сетевые походы.
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

// handleMe возвращает claims из контекста запроса — простейший эндпоинт,
// показывающий клиенту, как сервер его «увидел»: какой sub, какие scope,
// когда токен истечёт. Удобно для отладки интеграции и для демо.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "server_error",
			"claims отсутствуют в контексте")
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// handleAdmin — демо-эндпоинт, к которому пускают только пользователей с
// scope=admin. Сама проверка scope уже сделана выше в цепочке через
// RequireScope("admin"); если запрос дошёл до этого обработчика — значит,
// токен валиден и право admin у клиента есть.
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
