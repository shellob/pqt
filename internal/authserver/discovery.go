package authserver

import (
	"net/http"
)

// discoveryDocument — ответ /.well-known/oauth-authorization-server (RFC 8414).
//
// Поля собраны минимальным осмысленным набором для нашего сервера:
//   - issuer — обязательное поле по RFC 8414 §2.
//   - token_endpoint, jwks_uri, revocation_endpoint — адреса эндпоинтов,
//     которые сервер действительно реализует.
//   - response_types_supported — обязательное по RFC поле; у нас пустой
//     массив, потому что реализованы только сценарии на /auth/token
//     (password, refresh_token), а authorization-code flow с
//     response_type — нет.
//   - grant_types_supported — какие значения grant_type принимают
//     /auth/token и /auth/refresh.
//   - token_endpoint_auth_methods_supported — как клиент должен
//     представляться на /auth/token. У нас password grant без client_id,
//     поэтому "none".
//   - scopes_supported — реальный набор scope, выданный seed-пользователям.
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

// handleDiscovery — GET /.well-known/oauth-authorization-server (RFC 8414).
//
// Метаданные сервера: issuer и адреса всех эндпоинтов. Клиенты по этому
// документу автоматически узнают, куда отправлять запросы; инструменты
// вроде pqt-cli — где скачать JWKS, не задавая адрес руками.
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
