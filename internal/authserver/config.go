// Package authserver — это сервер авторизации PQ-AT для прототипа диссертации.
//
// Он реализует часть OAuth 2.0-совместимого сервера авторизации:
// эндпоинт выпуска токенов и публикацию JWKS. Refresh, revoke и discovery
// добавятся на этапах 7б и 7в.
package authserver

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pqt/keys"
)

// Config — все параметры запуска сервера.
//
// Большинство полей читается из переменных окружения через LoadFromEnv,
// но при программном запуске (например, в тестах) их можно задать напрямую.
type Config struct {
	// Addr — адрес для http.ListenAndServe. По умолчанию ":8080".
	Addr string

	// Issuer — URL сервера, который попадёт в claim iss выпускаемых токенов.
	// По умолчанию "http://localhost:8080".
	Issuer string

	// KeysDir — директория, где сервер хранит свои ключи в формате JWK.
	// При запуске:
	//   - если в ней есть файлы *.priv.jwk.json, они загружаются;
	//   - если нет, сервер генерирует один ключ алгоритма GenerateAlg
	//     и сохраняет его сюда.
	// По умолчанию "./keys".
	KeysDir string

	// DefaultKid — kid того ключа, которым сервер будет подписывать новые
	// токены. Если пусто — берётся первый по алфавиту kid из загруженных.
	DefaultKid string

	// AccessTTL — время жизни access-токена. По умолчанию 15 минут.
	AccessTTL time.Duration

	// RefreshTTL — время жизни refresh-токена. По умолчанию 30 дней.
	// Refresh используется для обновления access без повторного логина и
	// отзывается через POST /auth/revoke.
	RefreshTTL time.Duration

	// GenerateAlg — алгоритм для авто-генерации ключа, если KeysDir пуст.
	// По умолчанию hybrid-ecdsa-mldsa65 (целевой режим спецификации PQ-AT).
	GenerateAlg keys.Alg

	// BcryptCost — параметр сложности bcrypt при хешировании паролей
	// seed-пользователей на старте сервера. По умолчанию bcrypt.DefaultCost (10).
	// В тестах имеет смысл уменьшить до bcrypt.MinCost (4), чтобы старт
	// сервера занимал миллисекунды, а не секунду.
	BcryptCost int

	// Logger — куда писать диагностические сообщения. Если nil, используется
	// slog.Default().
	Logger *slog.Logger

	// Now — источник «текущего времени» для подстановки в claim iat/exp
	// при выпуске токенов. Если nil, используется time.Now. В тестах удобно
	// подменить на функцию, возвращающую фиксированное время.
	Now func() time.Time
}

// LoadFromEnv читает конфиг из переменных окружения, подставляя разумные
// значения по умолчанию для отсутствующих полей.
//
// Распознаваемые переменные:
//
//	PQT_ADDR           — адрес для Listen, например ":8080".
//	PQT_ISSUER         — URL, попадающий в claim iss.
//	PQT_KEYS_DIR       — директория с ключами.
//	PQT_DEFAULT_KID    — kid ключа для подписи новых токенов.
//	PQT_ACCESS_TTL     — длительность жизни access-токена (например, "15m").
//	PQT_GENERATE_ALG   — алгоритм для авто-генерации ключа.
//	PQT_BCRYPT_COST    — стоимость bcrypt (4..31).
func LoadFromEnv() Config {
	return Config{
		Addr:        envOr("PQT_ADDR", ":8080"),
		Issuer:      envOr("PQT_ISSUER", "http://localhost:8080"),
		KeysDir:     envOr("PQT_KEYS_DIR", "./keys"),
		DefaultKid:  envOr("PQT_DEFAULT_KID", ""),
		AccessTTL:   envDuration("PQT_ACCESS_TTL", 15*time.Minute),
		RefreshTTL:  envDuration("PQT_REFRESH_TTL", 30*24*time.Hour),
		GenerateAlg: keys.Alg(envOr("PQT_GENERATE_ALG", string(keys.AlgHybridECDSAMLDSA65))),
		BcryptCost:  envInt("PQT_BCRYPT_COST", bcrypt.DefaultCost),
	}
}

// validate подставляет значения по умолчанию для пустых полей и проверяет,
// что значения осмысленны.
func (c *Config) validate() error {
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	if c.Issuer == "" {
		c.Issuer = "http://localhost:8080"
	}
	if c.KeysDir == "" {
		c.KeysDir = "./keys"
	}
	if c.AccessTTL <= 0 {
		c.AccessTTL = 15 * time.Minute
	}
	if c.RefreshTTL <= 0 {
		c.RefreshTTL = 30 * 24 * time.Hour
	}
	if c.GenerateAlg == "" {
		c.GenerateAlg = keys.AlgHybridECDSAMLDSA65
	}
	if !c.GenerateAlg.Valid() {
		return fmt.Errorf("authserver: неизвестный алгоритм для GenerateAlg: %q", c.GenerateAlg)
	}
	if c.BcryptCost == 0 {
		c.BcryptCost = bcrypt.DefaultCost
	}
	if c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost {
		return fmt.Errorf("authserver: BcryptCost должен быть в диапазоне [%d, %d], получено %d",
			bcrypt.MinCost, bcrypt.MaxCost, c.BcryptCost)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func envInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
