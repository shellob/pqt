package authserver

import (
	"embed"
	"net/http"
	"strings"

	swgui "github.com/swaggest/swgui/v5"
)

// webuiFS — файлы демо-страницы и копия OpenAPI-спеки, вшитые прямо в
// бинарник через директиву //go:embed. После сборки сервер не требует
// ничего читать с диска: HTML, JS, CSS и openapi.yaml уже внутри файла
// pqt-authserver. Это удобно для развёртывания одной командой.
//
// Все файлы лежат в подпапке webui/ рядом с этим .go-файлом — у //go:embed
// есть ограничение: ходить «вверх» по директориям (через ../) ей запрещено,
// можно только в подпапки. Перегенерировать openapi.yaml — командой
// `go run ./cmd/pqt-openapi-gen` (она пишет одновременно сюда и в api/).
//
//go:embed webui/index.html webui/app.js webui/style.css webui/openapi.yaml
var webuiFS embed.FS

const (
	webUIIndexPath  = "webui/index.html"
	openAPIYAMLPath = "webui/openapi.yaml"
)

// staticAssets — белый список файлов, которые сервер отдаёт через /static/,
// и их content-type. Любой запрос вне этого списка получит 404, даже если
// сам файл есть в embed-FS.
//
// Можно было обойтись одной строчкой через http.FileServer поверх всей
// embed-FS — но мы сделали явный список по двум причинам:
//  1. http.FileServer на запрос вида /static/ (с слешем на конце, без
//     имени файла) молча отдал бы index.html — это его поведение по
//     умолчанию для директорий. У нас index.html обслуживается отдельным
//     обработчиком на /, и второй путь к нему через /static/ создавал бы
//     путаницу с кеширующими заголовками.
//  2. Без белого списка любой новый файл, добавленный в webui/, сразу
//     становился бы публично доступен через /static/. Сейчас, чтобы
//     отдать новый ассет, нужно осознанно дописать запись в эту map —
//     это страховка от случайной публикации внутренних файлов.
var staticAssets = map[string]struct {
	embedPath   string
	contentType string
}{
	"app.js":    {embedPath: "webui/app.js", contentType: "application/javascript; charset=utf-8"},
	"style.css": {embedPath: "webui/style.css", contentType: "text/css; charset=utf-8"},
}

// registerWebUI вешает на mux маршруты демо-страницы и Swagger UI:
//
//	GET /                          — index.html (формы логина/refresh/decode/...)
//	GET /static/{file}             — отдельные ассеты (app.js, style.css)
//	GET /docs/                     — Swagger UI с интерактивным просмотром API
//	GET /docs/openapi.yaml         — сама спецификация в YAML
//
// Маршруты API сервера (auth/*, .well-known/*) регистрируются отдельно
// и здесь не затрагиваются.
func (s *Server) registerWebUI(mux *http.ServeMux) {
	// {$} — синтаксис маршрутизатора Go 1.22, означает «совпадение строго
	// с корневым путём». Без него паттерн "GET /" совпадал бы с любым
	// GET-запросом на любой URL (это поведение старого http.ServeMux:
	// "/" — это префикс «всё, что не подобрал никто другой») и ломал
	// остальные маршруты. Например, GET /auth/token обязан возвращать
	// 405 Method Not Allowed (для /auth/token зарегистрирован только POST),
	// а без {$} он бы отдавал HTML главной страницы.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /docs/openapi.yaml", s.handleOpenAPI)

	// Swagger UI — готовый интерактивный просмотрщик OpenAPI-спецификаций.
	// Пакет swgui сам собирает HTML-страницу с формой «попробовать запрос»
	// и подключает к ней зашитые внутрь ассеты swagger-ui-dist (JS, CSS,
	// иконки) — никаких обращений к CDN, всё работает офлайн вместе с
	// бинарником сервера.
	swaggerHandler := swgui.NewHandler("PQ-AT API", "/docs/openapi.yaml", "/docs/")
	mux.Handle("GET /docs/", swaggerHandler)
}

// handleIndex отдаёт главную страницу демо — index.html из embed-FS.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := webuiFS.ReadFile(webUIIndexPath)
	if err != nil {
		s.cfg.Logger.Error("authserver: чтение index.html", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Cache-Control: no-cache говорит браузеру каждый раз спрашивать у
	// сервера, не изменилась ли страница, прежде чем брать её из своего
	// кеша. Это нужно, чтобы после перезапуска сервера с новой версткой
	// пользователь сразу видел свежий HTML — без ручного обновления через
	// Ctrl+Shift+R и принудительной очистки кеша.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// handleStatic отдаёт ассеты страницы (app.js, style.css) по белому списку
// staticAssets. Любой запрос вне списка получает 404 — так исключаются и
// случайная раздача index.html через /static/, и листинг содержимого
// embed-директории.
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
	// X-Content-Type-Options: nosniff запрещает браузеру самому угадывать
	// тип содержимого, если ему не нравится наш Content-Type. Без этого
	// заголовка браузер может «помочь» и интерпретировать, например,
	// текстовый файл как JavaScript — а это лазейка для атак, когда
	// файл с пользовательским содержимым исполняется как код.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// max-age=60 — клиенту разрешено кешировать ассет минуту. Для статики
	// этого хватает, чтобы при перезагрузке страницы не дёргать сеть, и
	// при этом обновления раскатываются за минуту.
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(data)
}

// handleOpenAPI отдаёт OpenAPI-спецификацию из embed-файла как application/yaml.
// Содержимое читает Swagger UI на /docs/, чтобы построить интерактивный
// просмотрщик API.
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
