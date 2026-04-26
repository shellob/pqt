package authserver_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pqt"
	"pqt/internal/authserver"
	"pqt/jwk"
	"pqt/keys"
	"pqt/token"
)

// newTestServer собирает Server с дешёвым конфигом для тестов:
//   - ключи генерируются в t.TempDir(), алгоритм ECDSA P-256 (быстрее остальных);
//   - bcrypt минимальной стоимости — иначе старт каждого теста занимает секунду;
//   - логгер пишет в /dev/null, чтобы не засорять вывод go test.
func newTestServer(t *testing.T) *authserver.Server {
	t.Helper()

	srv, err := authserver.New(authserver.Config{
		Issuer:      "https://test.example.com",
		KeysDir:     t.TempDir(),
		AccessTTL:   15 * time.Minute,
		GenerateAlg: keys.AlgECDSAP256,
		BcryptCost:  bcrypt.MinCost,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("authserver.New: %v", err)
	}
	return srv
}

// postForm — хелпер для POST-запроса с form-urlencoded телом.
func postForm(t *testing.T, srv *authserver.Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestToken_SuccessfulLogin(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"alice-password-2026"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("access_token пустой")
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, ожидали Bearer", resp.TokenType)
	}
	if resp.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d, ожидали положительное", resp.ExpiresIn)
	}
	if resp.Scope != "read write" {
		t.Fatalf("scope = %q, ожидали \"read write\"", resp.Scope)
	}
}

func TestToken_WrongPassword(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"wrong"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func TestToken_UnknownUser(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
		"username":   {"ghost"},
		"password":   {"whatever"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"client_credentials"},
		"username":   {"alice"},
		"password":   {"alice-password-2026"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	assertOAuthError(t, rec, "unsupported_grant_type")
}

func TestToken_MissingCredentials(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_request")
}

func TestToken_ScopeIsLimitedToUserAllowed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	// alice имеет "read write"; запрашивает "read write admin"
	// — admin должен быть отрезан.
	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"alice-password-2026"},
		"scope":      {"read write admin"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if resp.Scope != "read write" {
		t.Fatalf("scope = %q, ожидали \"read write\"", resp.Scope)
	}
}

func TestToken_OnlyPostMethodAllowed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, ожидали 405", rec.Code)
	}
}

func TestJWKS_PublishesPublicKeysOnly(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/pq-jwks", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q", got)
	}

	var set jwk.Set
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("разбор JWKS: %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatal("JWKS пустой")
	}
	for _, k := range set.Keys {
		if k.Kid == "" {
			t.Fatal("ключ в JWKS без kid")
		}
		// В публичном JWK не должно быть приватного материала.
		if k.D != "" || k.Priv != "" {
			t.Fatalf("в JWKS просочился приватный ключ (kid=%s, d=%v, priv=%v)",
				k.Kid, k.D != "", k.Priv != "")
		}
	}
}

func TestE2E_IssuedTokenValidatesAgainstJWKS(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	// 1. Получаем токен.
	rec := postForm(t, srv, "/auth/token", url.Values{
		"grant_type": {"password"},
		"username":   {"bob"},
		"password":   {"bob-password-2026"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("token status %d, body=%s", rec.Code, rec.Body.String())
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokResp); err != nil {
		t.Fatalf("разбор token-ответа: %v", err)
	}

	// 2. Скачиваем JWKS.
	jwksRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(jwksRec, httptest.NewRequest(http.MethodGet, "/.well-known/pq-jwks", nil))
	if jwksRec.Code != http.StatusOK {
		t.Fatalf("jwks status %d", jwksRec.Code)
	}
	var set jwk.Set
	if err := json.Unmarshal(jwksRec.Body.Bytes(), &set); err != nil {
		t.Fatalf("разбор jwks: %v", err)
	}

	// 3. KeySource ищет ключ по kid из заголовка токена в jwk.Set.
	keySource := func(h token.Header) (keys.PublicKey, error) {
		j, ok := set.Find(h.Kid)
		if !ok {
			return nil, pqt.ErrKeyNotFound
		}
		return jwk.ParsePublic(j)
	}

	// 4. Полный Validate.
	claims, err := pqt.Validate([]byte(tokResp.AccessToken), pqt.ValidateOptions{
		KeySource:        keySource,
		Format:           token.FormatText,
		ExpectedIssuer:   srv.Issuer(),
		ExpectedAudience: srv.Issuer(),
		Clock:            time.Now,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Sub != "bob" {
		t.Fatalf("claims.Sub = %q, ожидали bob", claims.Sub)
	}
	if claims.Scope != "read" {
		t.Fatalf("claims.Scope = %q, ожидали read", claims.Scope)
	}
}

func TestKeyStore_PicksUpExistingKeysOnRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Первый старт — сервер сам сгенерирует ключ.
	cfg := authserver.Config{
		KeysDir:     dir,
		Issuer:      "https://test.example.com",
		GenerateAlg: keys.AlgECDSAP256,
		BcryptCost:  bcrypt.MinCost,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	first, err := authserver.New(cfg)
	if err != nil {
		t.Fatalf("первый New: %v", err)
	}
	firstSet, err := getJWKSSet(t, first)
	if err != nil {
		t.Fatal(err)
	}

	// Второй старт с той же директорией — ключ должен подхватиться, а не
	// сгенерироваться заново.
	second, err := authserver.New(cfg)
	if err != nil {
		t.Fatalf("второй New: %v", err)
	}
	secondSet, err := getJWKSSet(t, second)
	if err != nil {
		t.Fatal(err)
	}

	if len(firstSet.Keys) != 1 || len(secondSet.Keys) != 1 {
		t.Fatalf("ожидали по одному ключу в обоих JWKS, получили %d и %d",
			len(firstSet.Keys), len(secondSet.Keys))
	}
	if firstSet.Keys[0].Kid != secondSet.Keys[0].Kid {
		t.Fatalf("kid не совпал между перезапусками: %q vs %q",
			firstSet.Keys[0].Kid, secondSet.Keys[0].Kid)
	}
}

func getJWKSSet(t *testing.T, srv *authserver.Server) (jwk.Set, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/pq-jwks", nil))
	if rec.Code != http.StatusOK {
		return jwk.Set{}, fmt.Errorf("jwks status %d", rec.Code)
	}
	var set jwk.Set
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		return jwk.Set{}, err
	}
	return set, nil
}

func assertOAuthError(t *testing.T, rec *httptest.ResponseRecorder, expectedCode string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("разбор ошибки: %v (body=%s)", err, rec.Body.String())
	}
	if body.Error != expectedCode {
		t.Fatalf("error = %q, ожидали %q", body.Error, expectedCode)
	}
}
