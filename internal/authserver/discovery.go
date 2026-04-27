package authserver

import (
	"net/http"
)

// discoveryDocument — тело ответа на /.well-known/oauth-authorization-server.
//
// Это «паспорт» OAuth-сервера по RFC 8414. Клиент дёргает один URL и из
// JSON-ответа узнаёт, куда ему отправлять реальные запросы — на какой
// адрес выпускать токен, где брать публичные ключи, какие grant-ы
// поддерживаются. Без этого документа клиент или человек должен прописывать
// все адреса вручную в конфиге.
//
// Поля собраны минимальным осмысленным набором именно для нашего сервера:
//   - issuer — кто выпускает токены, обязательное поле по RFC 8414 §2.
//   - token_endpoint, jwks_uri, revocation_endpoint — конкретные адреса
//     эндпоинтов, которые сервер действительно реализует.
//   - response_types_supported — обязательное поле RFC. Это значения для
//     authorization code flow (например, "code" или "token"), который у
//     нас не реализован. Пустой массив честно говорит: «таких сценариев
//     здесь нет, не пробуй».
//   - grant_types_supported — какие значения grant_type принимают наши
//     /auth/token и /auth/refresh. Только password и refresh_token.
//   - token_endpoint_auth_methods_supported — как клиент должен
//     представляться при запросе токена. У нас password grant без
//     регистрации клиентов, поэтому единственный метод — "none"
//     (клиент не аутентифицируется отдельно от пользователя).
//   - scopes_supported — реальный набор scope, выданный seed-пользователям
//     (read/write/admin).
type discoveryDocument struct {
	Issuer                                 string   `json:"issuer"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	JWKSURI                                string   `json:"jwks_uri"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                        []string `json:"scopes_supported"`
}

// handleDiscovery — GET /.well-known/oauth-authorization-server.
//
// Возвращает discoveryDocument в JSON. Клиенты (включая наш pqt-cli и
// вебка из webui/) дёргают этот URL один раз при старте и дальше уже знают
// точные адреса для запроса токена, отзыва и набора публичных ключей —
// не нужно прописывать каждый эндпоинт в конфиге руками.
//
// Cache-Control: max-age=300 (5 минут) — документ меняется крайне редко
// (только при перенастройке сервера), так что 5 минут на стороне клиента
// безопасны и снижают нагрузку.
func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := discoveryDocument{
		Issuer:                                 s.cfg.Issuer,
		TokenEndpoint:                          s.cfg.Issuer + "/auth/token",
		JWKSURI:                                s.cfg.Issuer + "/.well-known/pq-jwks",
		RevocationEndpoint:                     s.cfg.Issuer + "/auth/revoke",
		ResponseTypesSupported:                 []string{},
		GrantTypesSupported:                    []string{"password", "refresh_token"},
		TokenEndpointAuthMethodsSupported:      []string{"none"},
		RevocationEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                        []string{"read", "write", "admin"},
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	s.writeJSON(w, http.StatusOK, doc)
}
