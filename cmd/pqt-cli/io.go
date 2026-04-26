package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"pqt/jwk"
	"pqt/token"
)

// readJWK читает JWK из JSON-файла.
func readJWK(path string) (jwk.JWK, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("читаем JWK %q: %w", path, err)
	}
	var j jwk.JWK
	if err := json.Unmarshal(data, &j); err != nil {
		return jwk.JWK{}, fmt.Errorf("разбор JWK %q: %w", path, err)
	}
	return j, nil
}

// writeJWK пишет JWK в JSON-файл с отступами — так удобнее читать
// глазами и сравнивать diff'ом.
func writeJWK(path string, j jwk.JWK) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("сериализация JWK: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("запись %q: %w", path, err)
	}
	return nil
}

// readClaims читает Claims из JSON-файла. Используются стандартные имена
// полей (sub, iss, aud, exp, iat, jti, scope) — те же, что и в JWT.
func readClaims(path string) (token.Claims, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return token.Claims{}, fmt.Errorf("читаем claims %q: %w", path, err)
	}
	var c token.Claims
	if err := json.Unmarshal(data, &c); err != nil {
		return token.Claims{}, fmt.Errorf("разбор claims %q: %w", path, err)
	}
	return c, nil
}

// readTokenBytes читает токен из файла. Для текстового формата дополнительно
// убирает завершающий перевод строки, который многие редакторы добавляют сами.
func readTokenBytes(path string, format token.Format) ([]byte, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("читаем токен %q: %w", path, err)
	}
	if format == token.FormatText {
		// trim trailing CR/LF
		for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
			data = data[:len(data)-1]
		}
	}
	return data, nil
}

// writeBytes пишет байты в файл по пути path; если path пустой — в w.
// Для текстового формата дописывает перевод строки в stdout, чтобы вывод
// нормально смотрелся в терминале.
func writeBytes(path string, data []byte, format token.Format, w io.Writer) error {
	if path == "" {
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("запись в stdout: %w", err)
		}
		if format == token.FormatText {
			if _, err := w.Write([]byte("\n")); err != nil {
				return fmt.Errorf("запись в stdout: %w", err)
			}
		}
		return nil
	}
	// 0o600: токен может содержать чувствительные claims (sub, scope), и
	// в локальной разработке безопаснее по умолчанию ограничить права чтения
	// владельцем. Если нужен общий доступ — пользователь сам сделает chmod.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("запись %q: %w", path, err)
	}
	return nil
}
