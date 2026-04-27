package authserver

import (
	"embed"
	"net/http"
	"strings"

	swgui "github.com/swaggest/swgui/v5"
)

// Статика демо-страницы и копия OpenAPI-спеки. Лежит в подпапке webui/,
// чтобы embed мог увидеть её без пути «..» — это требование go:embed.
// Регенерация openapi.yaml — командой `go run ./cmd/pqt-openapi-gen`.
//
//go:embed webui/index.html webui/app.js webui/style.css webui/openapi.yaml
var webuiFS embed.FS

const (
	webUIIndexPath  = "webui/index.html"
	openAPIYAMLPath = "webui/openapi.yaml"
)

// staticAssets — белый список файлов, доступных через /static/. Используется
// явный список, а не http.FileServer над всем embed-делом: иначе можно было
// бы случайно отдавать index.html через /static/, и при изменении набора
// файлов поверхность раздачи менялась бы непредсказуемо.
var staticAssets = map[string]struct {
	embedPath   string
	contentType string
}{
	"app.js":    {embedPath: "webui/app.js", contentType: "application/javascript; charset=utf-8"},
	"style.css": {embedPath: "webui/style.css", contentType: "text/css; charset=utf-8"},
}

// registerWebUI вешает на mux маршруты демо-страницы и Swagger UI.
//
//	GET /                          — index.html (форма для логина/refresh/decode/...)
//	GET /static/{file}             — отдельные ассеты (app.js, style.css)
//	GET /docs/                     — Swagger UI (встроенный в swgui)
//	GET /docs/openapi.yaml         — спецификация в YAML
//
// Регистрация только этих эндпоинтов; всё API сервера (auth/*, .well-known/*)
// остаётся на тех же URL, что и раньше.
func (s *Server) registerWebUI(mux *http.ServeMux) {
	// {$} — Go 1.22 mux: точно корневой путь, не префикс. Без этого паттерн
	// "GET /" матчил бы любой GET на любой URL и ломал поведение остальных
	// маршрутов (например, GET /auth/token — должен быть 405, а не отдавать
	// index.html).
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /docs/openapi.yaml", s.handleOpenAPI)

	// Swagger UI обслуживается готовым handler'ом из swgui — он сам отдаёт
	// HTML-страницу и подключает встроенные swagger-ui-dist ассеты.
	swaggerHandler := swgui.NewHandler("PQ-AT API", "/docs/openapi.yaml", "/docs/")
	mux.Handle("GET /docs/", swaggerHandler)
}

// handleIndex отдаёт главную страницу демо.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := webuiFS.ReadFile(webUIIndexPath)
	if err != nil {
		s.cfg.Logger.Error("authserver: чтение index.html", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// no-cache на index.html: перезапустили сервер, обновили UI — изменения
	// видны без ctrl-shift-r у клиента.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// handleStatic отдаёт ассеты страницы по белому списку staticAssets. Любой
// запрос вне списка возвращает 404 — это исключает случайную раздачу
// index.html через /static/ и листинг embed-директории.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	asset, ok := staticAssets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := webuiFS.ReadFile(asset.embedPath)
	if err != nil {
		s.cfg.Logger.Error("authserver: чтение статики", "name", name, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(data)
}

// handleOpenAPI отдаёт спецификацию из embed-файла как application/yaml.
func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	data, err := webuiFS.ReadFile(openAPIYAMLPath)
	if err != nil {
		s.cfg.Logger.Error("authserver: чтение openapi.yaml", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(data)
}
