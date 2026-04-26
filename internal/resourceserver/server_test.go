package resourceserver_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pqt/internal/authserver"
	"pqt/internal/resourceserver"
	"pqt/keys"
	"pqt/token"
)

// pair — упрощённая копия tokenPair из тестов authserver: нам нужны только
// access и refresh строки, остальное игнорируем.
type pair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// envSetup поднимает реальный auth-сервер на httptest.Server и rest-сервер,
// смотрящий на него. Возвращает обоих + хелпер для логина.
type envSetup struct {
	auth     *authserver.Server
	authHTTP *httptest.Server
	resource *resourceserver.Server
}

func newEnv(t *testing.T) *envSetup {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	authSrv, err := authserver.New(authserver.Config{
		Issuer:      "http://auth.test",
		KeysDir:     t.TempDir(),
		AccessTTL:   15 * time.Minute,
		GenerateAlg: keys.AlgECDSAP256, // быстрее всех — для скорости тестов
		BcryptCost:  bcrypt.MinCost,
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("authserver.New: %v", err)
	}

	authHTTP := httptest.NewServer(authSrv.Handler())
	t.Cleanup(authHTTP.Close)

	// ExpectedIssuer берём из реального authSrv.Issuer(), но обращаемся за
	// JWKS на httptest URL — поэтому AuthServerBaseURL = httptest URL.
	resourceSrv, err := resourceserver.New(resourceserver.Config{
		AuthServerBaseURL: authHTTP.URL,
		ExpectedIssuer:    authSrv.Issuer(),
		ExpectedAudience:  authSrv.Issuer(),
		Logger:            logger,
	})
	if err != nil {
		t.Fatalf("resourceserver.New: %v", err)
	}

	return &envSetup{auth: authSrv, authHTTP: authHTTP, resource: resourceSrv}
}

// login логинится в реальный auth-сервер через httptest и возвращает токены.
func (e *envSetup) login(t *testing.T, username, password string) pair {
	t.Helper()

	body := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	}.Encode()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, e.authHTTP.URL+"/auth/token", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var p pair
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return p
}

// callResource дёргает resource-сервер с заданным path и токеном.
// Если token == "" — заголовок Authorization не ставится.
func (e *envSetup) callResource(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.resource.Handler().ServeHTTP(rec, req)
	return rec
}

func TestMe_ReturnsClaimsForValidToken(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	tokens := env.login(t, "alice", "alice-password-2026")

	rec := env.callResource(t, "/me", tokens.AccessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}

	var got token.Claims
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got.Sub != "alice" {
		t.Fatalf("sub = %q, ожидали alice", got.Sub)
	}
	if got.Scope != "read write" {
		t.Fatalf("scope = %q, ожидали \"read write\"", got.Scope)
	}
}

func TestMe_RejectsRequestWithoutAuthHeader(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	rec := env.callResource(t, "/me", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	assertErrorCode(t, rec, "invalid_request")
}

func TestMe_RejectsBasicAuth(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Basic abc=")
	rec := httptest.NewRecorder()
	env.resource.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestMe_RejectsBearerWithoutToken(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer    ")
	rec := httptest.NewRecorder()
	env.resource.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestMe_RejectsInvalidToken(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	rec := env.callResource(t, "/me", "not.a.real.token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestMe_RejectsTamperedToken(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	tokens := env.login(t, "alice", "alice-password-2026")

	// Меняем один байт в середине base64-строки токена.
	bs := []byte(tokens.AccessToken)
	if bs[len(bs)/2] == 'A' {
		bs[len(bs)/2] = 'B'
	} else {
		bs[len(bs)/2] = 'A'
	}

	rec := env.callResource(t, "/me", string(bs))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	assertErrorCode(t, rec, "invalid_token")
}

func TestAdmin_AllowedForAdminScope(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	tokens := env.login(t, "charlie", "charlie-password-2026") // read write admin

	rec := env.callResource(t, "/admin", tokens.AccessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if resp["sub"] != "charlie" {
		t.Fatalf("sub = %v", resp["sub"])
	}
}

func TestAdmin_DeniedWithoutScope(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	tokens := env.login(t, "alice", "alice-password-2026") // read write, без admin

	rec := env.callResource(t, "/admin", tokens.AccessToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec, "insufficient_scope")
}

func TestAdmin_RejectsRequestWithoutToken(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	// /admin сначала проходит RequireValidToken — там не будет токена,
	// упадём с 401, не дойдя до scope-проверки.
	rec := env.callResource(t, "/admin", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRotation_NewAccessFromRefreshIsValidOnResource(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	first := env.login(t, "bob", "bob-password-2026")

	// Делаем refresh: новый access выпускается тем же ключом, должен
	// валидироваться resource-сервером без отдельного refresh JWKS.
	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
	}.Encode()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, env.authHTTP.URL+"/auth/refresh", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status %d", resp.StatusCode)
	}
	var second pair
	if err := json.NewDecoder(resp.Body).Decode(&second); err != nil {
		t.Fatalf("разбор: %v", err)
	}

	rec := env.callResource(t, "/me", second.AccessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestNotFound_ReturnsExpected(t *testing.T) {
	t.Parallel()
	env := newEnv(t)

	rec := env.callResource(t, "/not-an-endpoint", "")
	// Нет такого маршрута → 404 от ServeMux. Middleware при этом не
	// активируется, потому что mux.Handle цепляет middleware только на
	// конкретные маршруты.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, expectedCode string) {
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
