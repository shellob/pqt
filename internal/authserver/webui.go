package authserver

import (
	"embed"
	"net/http"
	"strings"

	swgui "github.com/swaggest/swgui/v5"
)

// Статика демо-страницы и копия OpenAPI-спеки. Файлы лежат в подпапке
// webui/ рядом с этим файлом — этого требует директива //go:embed: ходить
// «вверх» на ../ ей запрещено, поэтому держим всё в локальной поддиректории.
// Перегенерировать openapi.yaml — командой `go run ./cmd/pqt-openapi-gen`.
//
//go:embed webui/index.html webui/app.js webui/style.css webui/openapi.yaml
var webuiFS embed.FS

const (
	webUIIndexPath  = "webui/index.html"
	openAPIYAMLPath = "webui/openapi.yaml"
)

// staticAssets — белый список файлов, которые отдаются через /static/.
// Сделано явным списком, а не через http.FileServer поверх всей embed-FS,
// по двум причинам: (1) http.FileServer на /static/ молча отдал бы
// index.html (это его дефолтное поведение для директорий) — а у нас
// index.html обслуживается отдельно через /; (2) при добавлении новых
// файлов в webui/ они бы автоматически становились публично доступны
// под /static/, что неожиданно расширяет поверхность раздачи.
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
	// {$} — синтаксис Go 1.22 mux, означающий «строго корневой путь, а не
	// префикс». Без него паттерн "GET /" совпадал бы с любым GET-запросом
	// на любой URL и ломал поведение остальных маршрутов: например,
	// GET /auth/token обязан возвращать 405 Method Not Allowed, а не
	// отдавать главную страницу.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /docs/openapi.yaml", s.handleOpenAPI)

	// Swagger UI обслуживается готовым обработчиком из swgui — он сам отдаёт
	// HTML-страницу и подключает встроенные внутри пакета ассеты
	// swagger-ui-dist (без обращения к CDN).
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
	// no-cache на index.html: после перезапуска сервера и обновления
	// HTML-разметки клиент сразу видит свежую страницу, без ctrl-shift-r
	// и обхода кэша браузера.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// handleStatic отдаёт ассеты страницы по белому списку staticAssets. Любой
// запрос вне этого списка возвращает 404 — так исключается и случайная
// раздача index.html через /static/, и листинг содержимого embed-директории.
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
