// Package openapi программно собирает OpenAPI-документ для всех HTTP-эндпоинтов
// проекта pqt — auth-сервера (pqt-authserver) и сервера ресурсов (pqt-resource).
//
// OpenAPI — это стандарт описания HTTP API в машинно-читаемом виде (JSON или
// YAML). По такому документу инструменты автоматически генерируют клиентов,
// валидируют запросы, рисуют интерактивные просмотрщики (Swagger UI) и
// проверяют ответы тестами.
//
// Здесь выбран подход «code-first»: путь, метод, тело запроса и схему ответа
// мы один раз описываем в этом Go-файле через типы из библиотеки kin-openapi.
// Сам YAML потом генерируется командой `go run ./cmd/pqt-openapi-gen` и
// кладётся в api/openapi.yaml и в webui/. Тест TestSpec_IsValid через
// spec.Validate(ctx) дополнительно гарантирует, что документ синтаксически
// валидный — если кто-то что-то опечатает в схемах, рассинхрон ловится на CI.
//
// Альтернатива «schema-first» (написать YAML руками, генерировать код по
// нему) для нашего размера API получалась тяжелее: мало эндпоинтов, простые
// схемы, удобнее держать описание рядом с реализацией.
package openapi

import (
	"github.com/getkin/kin-openapi/openapi3"
)

// Версии и адреса по умолчанию, которые запекаются в документ. Менять
// эти значения нужно осознанно: по specVersion инструменты определяют,
// какую версию OpenAPI они должны разбирать; по docVersion — версию
// именно нашего API; URL-ы становятся выпадающим списком серверов в
// Swagger UI, и Try-it-out отправляет запросы по выбранному из них.
const (
	specVersion = "3.1.0"
	docVersion  = "1.0.0"

	authServerURL     = "http://localhost:8080"
	resourceServerURL = "http://localhost:8081"

	bearerScheme = "BearerAuth"
)

// Build собирает OpenAPI-документ из частей: схемы переиспользуемых типов,
// списки серверов и тегов, описания путей. Возвращаемый объект полностью
// готов и для сериализации в JSON/YAML (через стандартные пакеты), и для
// проверки целостности через openapi3.T.Validate(ctx).
func Build() *openapi3.T {
	schemas := buildSchemas()
	doc := &openapi3.T{
		OpenAPI: specVersion,
		Info: &openapi3.Info{
			Title:       "PQ-AT API",
			Version:     docVersion,
			Description: "Прототип постквантового токена доступа (PQ-AT). Включает сервер авторизации и сервер ресурсов.",
			Contact: &openapi3.Contact{
				Name: "Тимофеенко С. В.",
				URL:  "https://github.com/shellob/pqt",
			},
		},
		Servers: openapi3.Servers{
			{URL: authServerURL, Description: "pqt-authserver (по умолчанию)"},
			{URL: resourceServerURL, Description: "pqt-resource"},
		},
		Components: &openapi3.Components{
			Schemas:         schemas,
			SecuritySchemes: buildSecuritySchemes(),
		},
		Paths: openapi3.NewPaths(),
		Tags: openapi3.Tags{
			{Name: "auth", Description: "Эндпоинты сервера авторизации"},
			{Name: "well-known", Description: "Стандартные публичные эндпоинты (JWKS, OAuth metadata)"},
			{Name: "resource", Description: "Защищённые эндпоинты сервера ресурсов"},
		},
	}

	addAuthPaths(doc, schemas)
	addWellKnownPaths(doc, schemas)
	addResourcePaths(doc, schemas)

	return doc
}

// schemaRef строит ссылку на одну из переиспользуемых схем — заполняет
// одновременно поле Ref (текстовая ссылка вида #/components/schemas/Имя,
// которая попадёт в финальный YAML) и поле Value (тот же объект схемы
// прямо в памяти). Value нужен, чтобы при валидации документа в коде
// разбиратель ссылок не пытался лезть на диск или в сеть, а сразу нашёл
// нужное в той же структуре. Без Value пришлось бы заводить отдельный
// Loader, что для одного процесса сборки оверкилл.
func schemaRef(schemas openapi3.Schemas, name string) *openapi3.SchemaRef {
	return &openapi3.SchemaRef{
		Ref:   "#/components/schemas/" + name,
		Value: schemas[name].Value,
	}
}

// buildSecuritySchemes описывает способ авторизации — у нас он один:
// Bearer-токен PQ-AT в заголовке Authorization. В Swagger UI этот блок
// проявится как кнопка «Authorize», в которую вставляется токен; после
// этого Try-it-out начнёт автоматически добавлять заголовок к запросам.
// Применяется только к эндпоинтам resource-сервера (/me, /admin) —
// эндпоинты auth-сервера публичные, на них токен не нужен.
func buildSecuritySchemes() openapi3.SecuritySchemes {
	return openapi3.SecuritySchemes{
		bearerScheme: &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "PQ-AT",
				Description:  "Access-токен PQ-AT, выпущенный pqt-authserver через POST /auth/token.",
			},
		},
	}
}

// buildSchemas описывает все типы данных, которые встречаются больше одного
// раза в API: ответы /auth/token, формат ошибки, JWK, JWK Set, метаданные
// сервера, claims токена. Один раз описанная схема в YAML переиспользуется
// через ссылки `$ref: "#/components/schemas/Имя"`, а не дублируется
// каждый раз — иначе документ распух бы кратно.
func buildSchemas() openapi3.Schemas {
	return openapi3.Schemas{
		"TokenResponse": &openapi3.SchemaRef{
			Value: openapi3.NewObjectSchema().
				WithProperty("access_token", openapi3.NewStringSchema()).
				WithProperty("token_type", openapi3.NewStringSchema().WithEnum("Bearer")).
				WithProperty("expires_in", openapi3.NewIntegerSchema()).
				WithProperty("refresh_token", openapi3.NewStringSchema()).
				WithProperty("refresh_expires_in", openapi3.NewIntegerSchema()).
				WithProperty("scope", openapi3.NewStringSchema()).
				WithRequired([]string{"access_token", "token_type", "expires_in"}),
		},
		"OAuthError": &openapi3.SchemaRef{
			Value: openapi3.NewObjectSchema().
				WithProperty("error", openapi3.NewStringSchema()).
				WithProperty("error_description", openapi3.NewStringSchema()).
				WithRequired([]string{"error"}),
		},
		"JWK": &openapi3.SchemaRef{
			Value: openapi3.NewObjectSchema().
				WithProperty("kty", openapi3.NewStringSchema().WithEnum("EC", "MLDSA", "Hybrid")).
				WithProperty("alg", openapi3.NewStringSchema()).
				WithProperty("kid", openapi3.NewStringSchema()).
				WithProperty("use", openapi3.NewStringSchema()).
				WithProperty("crv", openapi3.NewStringSchema()).
				WithProperty("x", openapi3.NewStringSchema()).
				WithProperty("y", openapi3.NewStringSchema()).
				WithProperty("pub", openapi3.NewStringSchema()).
				WithProperty("components", openapi3.NewArraySchema().WithItems(openapi3.NewObjectSchema())).
				WithRequired([]string{"kty"}),
		},
		"JWKSet": &openapi3.SchemaRef{
			Value: openapi3.NewObjectSchema().
				WithProperty("keys", openapi3.NewArraySchema().WithItems(
					openapi3.NewSchema().NewRef().Value)).
				WithRequired([]string{"keys"}),
		},
		"Discovery": &openapi3.SchemaRef{
			Value: openapi3.NewObjectSchema().
				WithProperty("issuer", openapi3.NewStringSchema()).
				WithProperty("token_endpoint", openapi3.NewStringSchema()).
				WithProperty("jwks_uri", openapi3.NewStringSchema()).
				WithProperty("revocation_endpoint", openapi3.NewStringSchema()).
				WithProperty("response_types_supported", openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())).
				WithProperty("grant_types_supported", openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())).
				WithProperty("token_endpoint_auth_methods_supported", openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())).
				WithProperty("revocation_endpoint_auth_methods_supported", openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())).
				WithProperty("scopes_supported", openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())).
				WithRequired([]string{"issuer", "token_endpoint", "jwks_uri"}),
		},
		"Claims": &openapi3.SchemaRef{
			Value: openapi3.NewObjectSchema().
				WithProperty("sub", openapi3.NewStringSchema()).
				WithProperty("iss", openapi3.NewStringSchema()).
				WithProperty("aud", openapi3.NewStringSchema()).
				WithProperty("exp", openapi3.NewIntegerSchema().WithFormat("int64")).
				WithProperty("iat", openapi3.NewIntegerSchema().WithFormat("int64")).
				WithProperty("jti", openapi3.NewStringSchema()).
				WithProperty("scope", openapi3.NewStringSchema()).
				WithProperty("kind", openapi3.NewStringSchema().WithEnum("access", "refresh")),
		},
	}
}

func addAuthPaths(doc *openapi3.T, schemas openapi3.Schemas) {
	tokenResp := schemaRef(schemas, "TokenResponse")
	errResp := schemaRef(schemas, "OAuthError")
	// POST /auth/token
	doc.Paths.Set("/auth/token", &openapi3.PathItem{
		Post: &openapi3.Operation{
			Tags:        []string{"auth"},
			Summary:     "Выпустить пару access + refresh",
			Description: "OAuth 2.0 Resource Owner Password Credentials Grant (RFC 6749 §4.3).",
			RequestBody: formBody(
				"grant_type", "username", "password",
				[]string{"grant_type", "username", "password"},
				//nolint:gosec // это описания полей формы, а не реальные креды
				map[string]string{
					"grant_type": "Должно быть 'password'.",
					"username":   "Логин из seed-набора (alice/bob/charlie/dave).",
					"password":   "Пароль из seed-набора.",
					"scope":      "Запрашиваемые scope через пробел (опционально).",
				},
				[]string{"scope"},
			),
			Responses: openapi3.NewResponses(
				okJSON("Успешный логин — выпущена пара токенов.", tokenResp),
				errJSON(400, "Неправильные параметры запроса.", errResp),
				errJSON(401, "Неверный логин или пароль.", errResp),
			),
		},
	})

	// POST /auth/refresh
	doc.Paths.Set("/auth/refresh", &openapi3.PathItem{
		Post: &openapi3.Operation{
			Tags:        []string{"auth"},
			Summary:     "Обновить access по refresh-токену",
			Description: "Rotation: старый refresh инвалидируется, выдаётся новая пара.",
			RequestBody: formBody(
				"grant_type", "refresh_token", "",
				[]string{"grant_type", "refresh_token"},
				//nolint:gosec // это описания полей формы, а не реальные креды
				map[string]string{
					"grant_type":    "Должно быть 'refresh_token'.",
					"refresh_token": "Refresh-токен, выданный ранее POST /auth/token.",
				},
				nil,
			),
			Responses: openapi3.NewResponses(
				okJSON("Успешный rotation.", tokenResp),
				errJSON(400, "Неправильные параметры запроса.", errResp),
				errJSON(401, "Refresh-токен невалиден или уже использован.", errResp),
			),
		},
	})

	// POST /auth/revoke
	doc.Paths.Set("/auth/revoke", &openapi3.PathItem{
		Post: &openapi3.Operation{
			Tags:        []string{"auth"},
			Summary:     "Отозвать access или refresh-токен",
			Description: "RFC 7009. Access попадает в blacklist по jti, refresh-сессия удаляется. По §2.2 успех возвращается даже если токен не найден.",
			RequestBody: formBody(
				"token", "", "",
				[]string{"token"},
				//nolint:gosec // это описания полей формы, а не реальные креды
				map[string]string{
					"token":           "Сам токен, который нужно отозвать.",
					"token_type_hint": "Подсказка типа: access_token | refresh_token. Используется только если в токене нет claim kind.",
				},
				[]string{"token_type_hint"},
			),
			Responses: openapi3.NewResponses(
				okEmpty(200, "Токен отозван (или не найден — RFC 7009 §2.2)."),
				errJSON(400, "Не указан параметр token.", errResp),
			),
		},
	})
}

func addWellKnownPaths(doc *openapi3.T, schemas openapi3.Schemas) {
	jwksRef := schemaRef(schemas, "JWKSet")
	discoveryRef := schemaRef(schemas, "Discovery")

	doc.Paths.Set("/.well-known/pq-jwks", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Tags:        []string{"well-known"},
			Summary:     "Получить публичные ключи сервера",
			Description: "JWKS (RFC 7517 §5). Расширения PQ-AT: kty=MLDSA для постквантовой ML-DSA, kty=Hybrid для гибридной пары.",
			Responses: openapi3.NewResponses(
				okJSON("JWK Set с публичными ключами.", jwksRef),
			),
		},
	})

	doc.Paths.Set("/.well-known/oauth-authorization-server", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Tags:        []string{"well-known"},
			Summary:     "Метаданные сервера авторизации",
			Description: "OAuth 2.0 Authorization Server Metadata (RFC 8414).",
			Responses: openapi3.NewResponses(
				okJSON("Документ с адресами эндпоинтов и поддерживаемыми возможностями.", discoveryRef),
			),
		},
	})
}

func addResourcePaths(doc *openapi3.T, schemas openapi3.Schemas) {
	resourceOnly := openapi3.Servers{
		{URL: resourceServerURL, Description: "pqt-resource"},
	}
	requireBearer := openapi3.SecurityRequirements{
		{bearerScheme: []string{}},
	}
	claimsRef := schemaRef(schemas, "Claims")
	errResp := schemaRef(schemas, "OAuthError")

	doc.Paths.Set("/me", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Tags:        []string{"resource"},
			Summary:     "Вернуть claims текущего пользователя",
			Description: "Берёт claims из контекста, который ставит middleware RequireValidToken.",
			Servers:     &resourceOnly,
			Security:    &requireBearer,
			Responses: openapi3.NewResponses(
				okJSON("Claims токена.", claimsRef),
				errJSON(401, "Заголовок Authorization отсутствует или токен невалиден.", errResp),
			),
		},
	})

	doc.Paths.Set("/admin", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Tags:        []string{"resource"},
			Summary:     "Защищённый эндпоинт только для admin-scope",
			Description: "Требует scope=admin в claim scope. Без него возвращается 403 insufficient_scope.",
			Servers:     &resourceOnly,
			Security:    &requireBearer,
			Responses: openapi3.NewResponses(
				okEmpty(200, "Доступ разрешён."),
				errJSON(401, "Токен невалиден.", errResp),
				errJSON(403, "У токена нет scope=admin.", errResp),
			),
		},
	})
}

// formBody конструирует описание тела запроса в формате
// application/x-www-form-urlencoded — это та же кодировка, в которой
// HTML-формы по умолчанию шлют POST-запрос (key=value, разделённое & и
// процентным экранированием).
//
// Параметры:
//   - p1, p2, p3 — имена основных полей в нужном для документа порядке;
//     пустые строки пропускаются. Фиксированный порядок здесь только
//     для красоты вывода в YAML.
//   - required — какие поля обязательны (для эндпоинтов вроде /auth/token
//     это «grant_type, username, password»).
//   - descriptions — карта «имя поля → текст пояснения», что увидит
//     пользователь Swagger UI при наведении на поле формы.
//   - optional — необязательные поля, например scope в /auth/token: они
//     должны быть в схеме (иначе валидация запроса будет ругаться на
//     неизвестное поле), но в required их нет.
func formBody(p1, p2, p3 string, required []string, descriptions map[string]string, optional []string) *openapi3.RequestBodyRef {
	schema := openapi3.NewObjectSchema()
	for _, name := range collectFields(p1, p2, p3, optional) {
		field := openapi3.NewStringSchema()
		if desc, ok := descriptions[name]; ok {
			field.Description = desc
		}
		schema = schema.WithProperty(name, field)
	}
	schema = schema.WithRequired(required)
	return &openapi3.RequestBodyRef{
		Value: openapi3.NewRequestBody().
			WithRequired(true).
			WithContent(openapi3.Content{
				"application/x-www-form-urlencoded": &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: schema}},
			}),
	}
}

// collectFields склеивает позиционные имена p1/p2/p3 с дополнительным
// списком optional, отбрасывая пустые строки. Порядок результата важен —
// именно в нём поля попадут в YAML, и стабильный порядок позволяет diff
// сгенерированного файла оставаться маленьким при правках кода.
func collectFields(p1, p2, p3 string, optional []string) []string {
	out := make([]string, 0, 4)
	for _, n := range []string{p1, p2, p3} {
		if n != "" {
			out = append(out, n)
		}
	}
	out = append(out, optional...)
	return out
}

// okJSON — короткая запись для «успешный 200 с JSON-телом по схеме ref».
// Используется вместо ручного составления openapi3.ResponseRef в каждом
// эндпоинте — иначе вызовы внизу выглядели бы шумно.
func okJSON(description string, ref *openapi3.SchemaRef) openapi3.NewResponsesOption {
	resp := openapi3.NewResponse().
		WithDescription(description).
		WithJSONSchemaRef(ref)
	return openapi3.WithStatus(200, &openapi3.ResponseRef{Value: resp})
}

// okEmpty — короткая запись для ответа без тела (или для ответа, где
// тело клиенту не интересно). Например, /auth/revoke: успех — просто 200,
// никаких полезных данных.
func okEmpty(status int, description string) openapi3.NewResponsesOption {
	resp := openapi3.NewResponse().WithDescription(description)
	return openapi3.WithStatus(status, &openapi3.ResponseRef{Value: resp})
}

// errJSON — короткая запись для ошибочного ответа (4xx) с телом OAuthError.
// Поля error и error_description едины для auth- и resource-сервера —
// клиенту достаточно одного разборщика.
func errJSON(status int, description string, errRef *openapi3.SchemaRef) openapi3.NewResponsesOption {
	resp := openapi3.NewResponse().
		WithDescription(description).
		WithJSONSchemaRef(errRef)
	return openapi3.WithStatus(status, &openapi3.ResponseRef{Value: resp})
}
