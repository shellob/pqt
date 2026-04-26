package openapi_test

import (
	"context"
	"strings"
	"testing"

	"pqt/internal/openapi"
)

func TestSpec_IsValid(t *testing.T) {
	t.Parallel()

	doc := openapi.Build()

	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("OpenAPI-документ не прошёл валидацию: %v", err)
	}
}

func TestSpec_HasExpectedPaths(t *testing.T) {
	t.Parallel()

	doc := openapi.Build()

	expected := []string{
		"/auth/token",
		"/auth/refresh",
		"/auth/revoke",
		"/.well-known/pq-jwks",
		"/.well-known/oauth-authorization-server",
		"/me",
		"/admin",
	}
	for _, p := range expected {
		if doc.Paths.Find(p) == nil {
			t.Errorf("отсутствует путь %q в документе", p)
		}
	}
}

func TestSpec_ResourceEndpointsRequireBearerAuth(t *testing.T) {
	t.Parallel()

	doc := openapi.Build()

	// /me и /admin — оба должны требовать Bearer-авторизацию.
	for _, p := range []string{"/me", "/admin"} {
		path := doc.Paths.Find(p)
		if path == nil || path.Get == nil {
			t.Fatalf("путь %q не найден или нет метода GET", p)
		}
		if path.Get.Security == nil || len(*path.Get.Security) == 0 {
			t.Fatalf("у %q не задана security — Bearer-токен должен требоваться", p)
		}
	}
}

func TestSpec_YAMLContainsKeyEndpoints(t *testing.T) {
	t.Parallel()

	doc := openapi.Build()

	yamlBytes, err := doc.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	yaml := string(yamlBytes)
	for _, fragment := range []string{
		"/auth/token",
		"BearerAuth",
		"3.1.0",
		"PQ-AT",
	} {
		if !strings.Contains(yaml, fragment) {
			t.Errorf("в сериализованном документе нет фрагмента %q", fragment)
		}
	}
}
