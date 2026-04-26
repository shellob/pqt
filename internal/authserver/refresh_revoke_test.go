package authserver_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"pqt"
	"pqt/internal/authserver"
	"pqt/jwk"
	"pqt/keys"
	"pqt/token"
)

// loginAndDecodeTokens выполняет POST /auth/token и возвращает разобранный
// ответ. Используется в тестах refresh/revoke как стартовая точка.
func loginAndDecodeTokens(t *testing.T, srv *authserver.Server, username, password string) tokenPair {
	t.Helper()
	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login status %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp tokenPair
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор token-ответа: %v", err)
	}
	return resp
}

type tokenPair struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
	TokenType        string `json:"token_type"`
}

func TestToken_IssuesAccessAndRefresh(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	resp := loginAndDecodeTokens(t, srv, "alice", "alice-password-2026")
	if resp.AccessToken == "" {
		t.Fatal("access_token пустой")
	}
	if resp.RefreshToken == "" {
		t.Fatal("refresh_token пустой")
	}
	if resp.AccessToken == resp.RefreshToken {
		t.Fatal("access и refresh — одни и те же байты, должны различаться")
	}
	if resp.RefreshExpiresIn <= resp.ExpiresIn {
		t.Fatalf("refresh_expires_in (%d) должен быть больше expires_in (%d)",
			resp.RefreshExpiresIn, resp.ExpiresIn)
	}
}

func TestRefresh_RotatesTokens(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	first := loginAndDecodeTokens(t, srv, "alice", "alice-password-2026")

	rec := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status %d, body=%s", rec.Code, rec.Body.String())
	}

	var second tokenPair
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if second.AccessToken == "" || second.RefreshToken == "" {
		t.Fatal("после refresh не пришла полная пара токенов")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("новый refresh-токен совпадает со старым — rotation не сработал")
	}
	if second.Scope != "read write" {
		t.Fatalf("scope = %q, ожидали \"read write\"", second.Scope)
	}
}

func TestRefresh_ReplayIsRejected(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	first := loginAndDecodeTokens(t, srv, "alice", "alice-password-2026")

	// Первый refresh — успех.
	rec1 := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("первый refresh: status %d", rec1.Code)
	}

	// Повторный refresh с тем же токеном — replay, должен быть отвергнут.
	rec2 := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
	})
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replay refresh: status %d, ожидали 401, body=%s", rec2.Code, rec2.Body.String())
	}
	assertOAuthError(t, rec2, "invalid_grant")
}

func TestRefresh_UnknownTokenIsRejected(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"not.a.token"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func TestRefresh_AccessTokenInsteadOfRefreshIsRejected(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	pair := loginAndDecodeTokens(t, srv, "alice", "alice-password-2026")

	// Подсовываем access-токен в refresh-эндпоинт. Сервер должен заметить,
	// что kind != refresh, и отказать.
	rec := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {pair.AccessToken},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRefresh_BadGrantType(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"password"},
		"refresh_token": {"anything"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	assertOAuthError(t, rec, "unsupported_grant_type")
}

func TestRevoke_AccessTokenLandsInBlacklist(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	pair := loginAndDecodeTokens(t, srv, "alice", "alice-password-2026")

	// До revoke — токен валидируется.
	if _, err := pqt.Validate([]byte(pair.AccessToken), pqt.ValidateOptions{
		KeySource:        publicKeyFromJWKS(t, srv),
		Format:           token.FormatText,
		ExpectedIssuer:   srv.Issuer(),
		ExpectedAudience: srv.Issuer(),
		IsRevoked:        srv.IsRevoked,
	}); err != nil {
		t.Fatalf("до revoke токен должен быть валиден: %v", err)
	}

	// Revoke.
	rec := postForm(t, srv, "/auth/revoke", url.Values{
		"token":           {pair.AccessToken},
		"token_type_hint": {"access_token"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status %d", rec.Code)
	}

	// После revoke — Validator с IsRevoked отвергает.
	_, err := pqt.Validate([]byte(pair.AccessToken), pqt.ValidateOptions{
		KeySource:        publicKeyFromJWKS(t, srv),
		Format:           token.FormatText,
		ExpectedIssuer:   srv.Issuer(),
		ExpectedAudience: srv.Issuer(),
		IsRevoked:        srv.IsRevoked,
	})
	if !errors.Is(err, pqt.ErrTokenRevoked) {
		t.Fatalf("ожидали ErrTokenRevoked, получили %v", err)
	}
}

func TestRevoke_RefreshTokenRemovesSession(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	pair := loginAndDecodeTokens(t, srv, "alice", "alice-password-2026")

	rec := postForm(t, srv, "/auth/revoke", url.Values{
		"token":           {pair.RefreshToken},
		"token_type_hint": {"refresh_token"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status %d", rec.Code)
	}

	// После revoke — попытка обновиться отвергается.
	rec2 := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {pair.RefreshToken},
	})
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("refresh после revoke: status %d, ожидали 401", rec2.Code)
	}
}

func TestRevoke_GarbageTokenStillReturns200(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	// RFC 7009 §2.2: «успех» даже если токен не разобрался — иначе сервер
	// раскрывал бы факт его существования атакующему.
	rec := postForm(t, srv, "/auth/revoke", url.Values{
		"token": {"this-is-not-a-token"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, ожидали 200", rec.Code)
	}
}

func TestRevoke_RequiresTokenParam(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/revoke", url.Values{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestE2E_RotationKeepsValidatorHappy(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	// Получаем токены, обновляемся, проверяем что новый access валидируется.
	first := loginAndDecodeTokens(t, srv, "charlie", "charlie-password-2026")

	rec := postForm(t, srv, "/auth/refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d", rec.Code)
	}
	var second tokenPair
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("разбор: %v", err)
	}

	// Новый access валидируется через JWKS.
	claims, err := pqt.Validate([]byte(second.AccessToken), pqt.ValidateOptions{
		KeySource:        publicKeyFromJWKS(t, srv),
		Format:           token.FormatText,
		ExpectedIssuer:   srv.Issuer(),
		ExpectedAudience: srv.Issuer(),
		IsRevoked:        srv.IsRevoked,
	})
	if err != nil {
		t.Fatalf("Validate нового access: %v", err)
	}
	if claims.Sub != "charlie" {
		t.Fatalf("sub = %q", claims.Sub)
	}
	if claims.Kind != token.KindAccess {
		t.Fatalf("kind = %q, ожидали %q", claims.Kind, token.KindAccess)
	}
}

// publicKeyFromJWKS возвращает KeySource, который ищет ключ для проверки
// подписи в опубликованном сервером JWKS по kid из заголовка токена.
// Используется в тестах как имитация того, что делает внешний resource-сервер.
func publicKeyFromJWKS(t *testing.T, srv *authserver.Server) pqt.KeySource {
	t.Helper()
	set, err := getJWKSSet(t, srv)
	if err != nil {
		t.Fatalf("getJWKSSet: %v", err)
	}
	return func(h token.Header) (keys.PublicKey, error) {
		j, ok := set.Find(h.Kid)
		if !ok {
			return nil, pqt.ErrKeyNotFound
		}
		return jwk.ParsePublic(j)
	}
}
