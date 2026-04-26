// Package openapi программно собирает OpenAPI 3.1-документ для всего набора
// эндпоинтов проекта pqt: эндпоинты pqt-authserver и pqt-resource.
//
// Подход «code-first»: путь, метод и схему ответа задаём один раз в Go-коде,
// а YAML генерируется командой cmd/pqt-openapi-gen. Это гарантирует, что
// документ всегда согласован с реальной реализацией: достаточно тестом
// проверить, что Build() даёт валидный документ — рассинхрон с кодом
// поймается на CI.
package openapi

import (
	"github.com/getkin/kin-openapi/openapi3"
)

// Версии и адреса для документа. Менять — только осознанно.
const (
	specVersion = "3.1.0"
	docVersion  = "1.0.0"

	authServerURL     = "http://localhost:8080"
	resourceServerURL = "http://localhost:8081"

	bearerScheme = "BearerAuth"
)

// Build собирает OpenAPI 3.1-документ. Возвращаемый объект готов к
// сериализации в JSON/YAML или передаче в openapi3.T.Validate.
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

// schemaRef собирает SchemaRef, в котором заполнены и Ref (для сериализации),
// и Value (чтобы validator при программной сборке смог разрешить ссылку
// без отдельного Loader'а).
func schemaRef(schemas openapi3.Schemas, name string) *openapi3.SchemaRef {
	return &openapi3.SchemaRef{
		Ref:   "#/components/schemas/" + name,
		Value: schemas[name].Value,
	}
}

// buildSecuritySchemes описывает один способ авторизации — Bearer-токен PQ-AT
// в заголовке Authorization. Используется только на эндпоинтах
// resource-сервера; auth-эндпоинты публичные.
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

// buildSchemas — переиспользуемые схемы ответов и тел запросов.
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

// formBody — application/x-www-form-urlencoded body. Принимает имена
// нескольких ключевых полей в фиксированном порядке (для самодокументируемости),
// плюс полный список required и описания всех полей. additional — поля,
// которые попали в required-список как «иногда» — например, scope в /auth/token.
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

// collectFields собирает уникальный список имён полей из позиционных и
// дополнительных, отбрасывая пустые строки. Порядок: сначала позиционные,
// потом optional — это стабилизирует вывод в YAML.
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

// okJSON — Response 200 с JSON-телом по переданному SchemaRef.
func okJSON(description string, ref *openapi3.SchemaRef) openapi3.NewResponsesOption {
	resp := openapi3.NewResponse().
		WithDescription(description).
		WithJSONSchemaRef(ref)
	return openapi3.WithStatus(200, &openapi3.ResponseRef{Value: resp})
}

// okEmpty — Response без тела (или с произвольным телом, на которое нам всё равно).
func okEmpty(status int, description string) openapi3.NewResponsesOption {
	resp := openapi3.NewResponse().WithDescription(description)
	return openapi3.WithStatus(status, &openapi3.ResponseRef{Value: resp})
}

// errJSON — Response с OAuthError-телом для статусов 4xx.
func errJSON(status int, description string, errRef *openapi3.SchemaRef) openapi3.NewResponsesOption {
	resp := openapi3.NewResponse().
		WithDescription(description).
		WithJSONSchemaRef(errRef)
	return openapi3.WithStatus(status, &openapi3.ResponseRef{Value: resp})
}
