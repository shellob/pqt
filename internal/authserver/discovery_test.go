package authserver_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pqt/internal/authserver"
	"pqt/keys"
)

func TestDiscovery_PublishesEndpoints(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("разбор: %v", err)
	}

	expectedFields := map[string]string{
		"issuer":              "https://test.example.com",
		"token_endpoint":      "https://test.example.com/auth/token",
		"jwks_uri":            "https://test.example.com/.well-known/pq-jwks",
		"revocation_endpoint": "https://test.example.com/auth/revoke",
	}
	for field, expected := range expectedFields {
		got, ok := doc[field].(string)
		if !ok {
			t.Fatalf("поле %s отсутствует или не строка: %v", field, doc[field])
		}
		if got != expected {
			t.Fatalf("%s = %q, ожидали %q", field, got, expected)
		}
	}

	// Поле revocation_endpoint_auth_methods_supported обязательно нужно,
	// раз revocation_endpoint опубликован — клиенту надо знать, как на нём
	// аутентифицироваться. У нас "none" (как и token_endpoint).
	revAuth, _ := doc["revocation_endpoint_auth_methods_supported"].([]any)
	if len(revAuth) == 0 {
		t.Fatal("revocation_endpoint_auth_methods_supported отсутствует или пуст")
	}

	// Список grant_types_supported должен содержать password и refresh_token.
	grantTypes, _ := doc["grant_types_supported"].([]any)
	asStrings := make([]string, 0, len(grantTypes))
	for _, v := range grantTypes {
		if s, ok := v.(string); ok {
			asStrings = append(asStrings, s)
		}
	}
	for _, want := range []string{"password", "refresh_token"} {
		if !slices.Contains(asStrings, want) {
			t.Fatalf("grant_types_supported не содержит %q: %v", want, asStrings)
		}
	}
}

func TestDebug_PprofDisabledByDefault(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))

	// Без Debug=true маршрут не зарегистрирован — mux отдаст 404.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, ожидали 404 (pprof не должен быть доступен по умолчанию)", rec.Code)
	}
}

func TestDebug_PprofEnabledWhenDebugFlagSet(t *testing.T) {
	t.Parallel()
	srv, err := authserver.New(authserver.Config{
		Issuer:      "https://test.example.com",
		KeysDir:     t.TempDir(),
		AccessTTL:   15 * time.Minute,
		GenerateAlg: keys.AlgECDSAP256,
		BcryptCost:  bcrypt.MinCost,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Debug:       true,
	})
	if err != nil {
		t.Fatalf("authserver.New: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rec.Code, rec.Body.String())
	}
	// pprof.Index должен вернуть HTML-страницу со списком доступных профилей —
	// в ней обязательно есть ссылка на goroutine.
	if !strings.Contains(rec.Body.String(), "goroutine") {
		t.Fatalf("ответ /debug/pprof/ не похож на index pprof: %s", rec.Body.String())
	}
}
