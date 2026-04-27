// Команда pqt-openapi-gen генерирует OpenAPI-спеку из Go-кода
// (см. internal/openapi.Build).
//
// Запускается вручную перед коммитом:
//
//	go run ./cmd/pqt-openapi-gen
//
// По умолчанию пишет в две локации сразу:
//
//	api/openapi.yaml                         — публичный артефакт для чтения и CI;
//	internal/authserver/webui/openapi.yaml   — копия для embed в auth-сервер.
//
// Можно явно указать одну цель через --out path/to/openapi.yaml.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"pqt/internal/openapi"
)

// defaultPaths — куда писать YAML по умолчанию. Перечислены в порядке записи;
// первый используется в логах, остальные пишутся теми же байтами.
var defaultPaths = []string{
	"api/openapi.yaml",
	"internal/authserver/webui/openapi.yaml",
}

func main() {
	out := flag.String("out", "", "явный путь для YAML; если пустой, пишутся обе дефолтные локации")
	flag.Parse()

	targets := defaultPaths
	if *out != "" {
		targets = []string{*out}
	}

	if err := run(targets); err != nil {
		fmt.Fprintf(os.Stderr, "pqt-openapi-gen: %v\n", err)
		os.Exit(1)
	}
}

func run(targets []string) error {
	doc := openapi.Build()

	if err := doc.Validate(context.Background()); err != nil {
		return fmt.Errorf("документ невалиден: %w", err)
	}

	// MarshalJSON, потом sigs.k8s.io/yaml превращает JSON → YAML с сохранением
	// порядка полей. Прямой YAML-маршалинг через gopkg.in/yaml.v3 терял бы
	// json-теги, по которым у kin-openapi и описаны имена полей.
	jsonBytes, err := doc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("сериализация JSON: %w", err)
	}
	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return fmt.Errorf("JSON→YAML: %w", err)
	}

	for _, path := range targets {
		// 0o644: openapi.yaml — публичный документ (спецификация API),
		// смысла прятать его за 0o600 нет.
		if err := os.WriteFile(path, yamlBytes, 0o644); err != nil { //nolint:gosec // публичный документ
			return fmt.Errorf("запись %q: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "записано: %s (%d байт)\n", path, len(yamlBytes))
	}
	return nil
}
