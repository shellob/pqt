package authserver

import (
	"net/http"
)

// discoveryDocument — ответ /.well-known/oauth-authorization-server (RFC 8414).
//
// Поля выбраны минимальным осмысленным набором для нашего сервера:
//   - issuer — обязательное поле RFC 8414 §2.
//   - token_endpoint, jwks_uri, revocation_endpoint — endpoint'ы, которые
//     сервер действительно реализует.
//   - response_types_supported — обязательное поле; пустой массив, потому
//     что мы реализуем только token-endpoint flows (password, refresh_token),
//     а не authorization-code flow с response_type.
//   - grant_types_supported — какие grant_type принимает /auth/token и
//     /auth/refresh.
//   - token_endpoint_auth_methods_supported — как клиент аутентифицируется
//     на token-эндпоинте. У нас grant=password без client_id, поэтому "none".
//   - scopes_supported — фактический набор scope, известный seed-пользователям.
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
// Метаданные сервера: issuer и адреса эндпоинтов. Клиенты используют их,
// чтобы автоматически настроиться, а инструменты вроде pqt-cli — чтобы
// узнать JWKS-адрес без ручной конфигурации.
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
