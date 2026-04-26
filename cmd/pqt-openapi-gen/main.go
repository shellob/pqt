// Команда pqt-openapi-gen генерирует api/openapi.yaml из go-кода
// (см. internal/openapi.Build).
//
// Запускается вручную перед коммитом:
//
//	go run ./cmd/pqt-openapi-gen
//
// Если нужен другой путь:
//
//	go run ./cmd/pqt-openapi-gen --out path/to/openapi.yaml
//
// Файл api/openapi.yaml коммитится в репозиторий — это позволяет читать
// спеку (или открывать в Swagger UI) без запуска генератора.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"pqt/internal/openapi"
)

const defaultOut = "api/openapi.yaml"

func main() {
	out := flag.String("out", defaultOut, "куда записать YAML-файл")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "pqt-openapi-gen: %v\n", err)
		os.Exit(1)
	}
}

func run(outPath string) error {
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

	// 0o644: api/openapi.yaml — публичный документ (спецификация API),
	// смысла прятать его за 0o600 нет.
	if err := os.WriteFile(outPath, yamlBytes, 0o644); err != nil { //nolint:gosec // публичный документ
		return fmt.Errorf("запись %q: %w", outPath, err)
	}

	fmt.Fprintf(os.Stderr, "записано: %s (%d байт)\n", outPath, len(yamlBytes))
	return nil
}
