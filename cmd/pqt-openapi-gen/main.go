// Команда pqt-openapi-gen генерирует YAML-файл OpenAPI-спецификации из
// Go-кода (см. internal/openapi.Build). Запускается вручную, когда меняем
// схему API:
//
//	go run ./cmd/pqt-openapi-gen
//
// По умолчанию утилита пишет одни и те же байты в две разные точки:
//
//	api/openapi.yaml                          — публичный артефакт.
//	                                             Идёт в репозиторий, по нему
//	                                             ориентируются клиенты, IDE
//	                                             и CI.
//	internal/authserver/webui/openapi.yaml    — копия для embed в бинарник
//	                                             auth-сервера. Без неё
//	                                             Swagger UI на /docs/ ничего
//	                                             бы не показал, потому что
//	                                             директива //go:embed запекает
//	                                             файлы только из webui/.
//
// Если хочется записать только в одно место (например, чтобы пересобрать
// именно публичный артефакт), есть флаг `--out path/to/openapi.yaml`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"pqt/internal/openapi"
)

// defaultPaths — два пути, в которые утилита пишет YAML, когда флаг --out
// не задан. Записываются строго одни и те же байты: оба файла должны
// побайтово совпадать, иначе Swagger UI начнёт показывать одну схему, а
// клиенты ходить по другой.
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

	// Сначала сериализуем документ в JSON, потом конвертируем JSON в YAML
	// через sigs.k8s.io/yaml. Прямой маршалинг через gopkg.in/yaml.v3 не
	// подходит: kin-openapi описывает имена полей через json-теги (например,
	// `json:"openapi"`), а yaml.v3 понимает только yaml-теги — и без них
	// поля либо потеряются, либо запишутся под именами Go-структур
	// (Openapi вместо openapi). Через JSON порядок полей и их имена
	// сохраняются точно так, как задумано в схеме.
	jsonBytes, err := doc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("сериализация JSON: %w", err)
	}
	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return fmt.Errorf("JSON→YAML: %w", err)
	}

	for _, path := range targets {
		// Права 0o644: владелец читает и пишет, остальные — только читают.
		// openapi.yaml — публичная спецификация API, никаких секретов в ней
		// нет, поэтому жёстко ограничивать чтение, как мы делаем для
		// приватных ключей, тут не нужно.
		if err := os.WriteFile(path, yamlBytes, 0o644); err != nil { //nolint:gosec // публичный документ
			return fmt.Errorf("запись %q: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "записано: %s (%d байт)\n", path, len(yamlBytes))
	}
	return nil
}
