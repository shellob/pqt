package authserver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUI_IndexServesHTML(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "PQ-AT") {
		t.Fatalf("в index.html нет фрагмента \"PQ-AT\"")
	}
}

func TestWebUI_IndexNotMountedOnUnrelatedPaths(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	// Корневой паттерн зарегистрирован как "GET /{$}". GET на любой другой
	// URL без зарегистрированного handler'а должен дать 404, а не index.html.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/totally-not-an-endpoint", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, ожидали 404 — index не должен показываться на левых URL", rec.Code)
	}
}

func TestWebUI_RootRejectsNonGet(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	// Корень зарегистрирован как "GET /{$}", поэтому POST на корень обязан
	// дать 405 Method Not Allowed (а не 404 и не отдать index.html).
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, ожидали 405 на POST /", rec.Code)
	}
}

func TestWebUI_StaticRejectsUnknownAsset(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	// Доступ к /static/index.html, /static/openapi.yaml и любому другому
	// файлу вне белого списка — должен быть 404.
	for _, path := range []string{"/static/index.html", "/static/openapi.yaml", "/static/", "/static/nope.txt"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d, ожидали 404", path, rec.Code)
		}
	}
}

func TestWebUI_StaticServesAssets(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	for _, path := range []string{"/static/app.js", "/static/style.css"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("%s: пустое тело", path)
		}
	}
}

func TestWebUI_OpenAPISpecServed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/yaml") {
		t.Fatalf("Content-Type = %q, ожидали application/yaml", got)
	}
	body := rec.Body.String()
	for _, fragment := range []string{"openapi:", "/auth/token", "BearerAuth"} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("в openapi.yaml нет фрагмента %q", fragment)
		}
	}
}

func TestWebUI_SwaggerUIServesHTML(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/docs/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	// swgui отдаёт HTML-страницу со встроенным swagger-ui-bundle.
	if !strings.Contains(strings.ToLower(body), "swagger") {
		t.Fatalf("ответ /docs/ не похож на Swagger UI: %q", body[:min(200, len(body))])
	}
}
