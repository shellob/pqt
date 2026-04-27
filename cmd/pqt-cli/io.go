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

// writeJWK пишет JWK в JSON-файл с отступами по 2 пробела. Без отступов
// JSON получается одной длинной строкой, в которой ничего не разглядеть
// глазами и неудобно смотреть diff в git. Размер файла от форматирования
// почти не страдает (на типовом ключе разница в десятки байт).
//
// Права 0o600 — только чтение и запись для владельца. Через JWK мы пишем
// и приватные ключи, и публичные (внешний код знает, какой именно вызов
// нужен). Для приватных это критично; публичные тоже не делаем
// общедоступными по умолчанию — для шерить ключ владелец сам сделает chmod.
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

// readTokenBytes читает токен из файла. Для текстового формата отдельно
// срезает завершающие переводы строк (\n и \r): многие редакторы автоматически
// добавляют пустую строку в конец файла, и без срезания токен бы не разобрался
// (Base64url не допускает посторонних символов в конце). Для бинарного
// формата таких подчисток не делаем — там байт является байтом.
func readTokenBytes(path string, format token.Format) ([]byte, error) {
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("читаем токен %q: %w", path, err)
	}
	if format == token.FormatText {
		for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
			data = data[:len(data)-1]
		}
	}
	return data, nil
}

// writeBytes пишет байты в файл по пути path; если path пустой — в writer w
// (на практике — os.Stdout). Для текстового формата при выводе в writer
// дописывает перевод строки: иначе следующий промпт оболочки слипнется с
// последним символом токена. В файл переводы строк не добавляем — они бы
// сломали чтение через readTokenBytes у других утилит, которые не делают
// trim.
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
	// Права 0o600 — только владелец может читать и писать. В токене
	// в payload лежит чувствительная информация (sub — кто это, scope —
	// что ему можно). Если файл будет доступен на чтение всем, любой
	// локальный пользователь сможет утащить токен и до его exp ходить
	// с ним к серверу как владелец. Когда общий доступ нужен явно,
	// пользователь сам сделает chmod.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("запись %q: %w", path, err)
	}
	return nil
}
