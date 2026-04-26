// Package resourceserver — демо-сервер ресурсов PQ-AT для прототипа диссертации.
//
// Слой, который проверяет access-токены и пускает на защищённые эндпоинты
// только тех, у кого подпись валидная и scope подходящий. Использует те же
// функции pqt.Validate / jwk.Set, что и любой внешний клиент библиотеки.
package resourceserver

import (
	"log/slog"
	"os"
	"time"
)

// Config — параметры запуска resource-сервера.
type Config struct {
	// Addr — адрес для http.ListenAndServe. По умолчанию ":8081".
	Addr string

	// AuthServerBaseURL — базовый URL сервера авторизации, у которого
	// resource-сервер скачивает JWKS. Например, "http://localhost:8080".
	AuthServerBaseURL string

	// ExpectedIssuer — значение, которое должен иметь claim iss во входящих
	// токенах. По умолчанию совпадает с AuthServerBaseURL.
	ExpectedIssuer string

	// ExpectedAudience — значение, которое должен иметь claim aud. Если пусто —
	// проверка пропускается (для прототипа допустимо; в production-конфиге
	// здесь должен стоять id ресурс-сервера).
	ExpectedAudience string

	// Leeway — допустимая разница часов с auth-сервером.
	Leeway time.Duration

	// JWKSRefreshInterval — как часто фоном обновлять JWKS, чтобы подхватить
	// ротацию ключей. По умолчанию 5 минут.
	JWKSRefreshInterval time.Duration

	// HTTPTimeout — таймаут на сетевой запрос за JWKS. По умолчанию 5 секунд.
	HTTPTimeout time.Duration

	// Logger — куда писать диагностические сообщения.
	Logger *slog.Logger

	// Now — источник «текущего времени». В тестах удобно подменить.
	Now func() time.Time
}

// LoadFromEnv читает конфиг из переменных окружения.
//
// Распознаются:
//
//	PQT_RESOURCE_ADDR             — адрес для Listen, например ":8081".
//	PQT_AUTH_BASE_URL             — базовый URL auth-сервера.
//	PQT_RESOURCE_ISSUER           — ожидаемый iss; по умолчанию = PQT_AUTH_BASE_URL.
//	PQT_RESOURCE_AUDIENCE         — ожидаемый aud; по умолчанию пусто (без проверки).
//	PQT_RESOURCE_LEEWAY           — duration, по умолчанию 0.
//	PQT_RESOURCE_JWKS_REFRESH     — duration, по умолчанию 5m.
//	PQT_RESOURCE_HTTP_TIMEOUT     — duration, по умолчанию 5s.
func LoadFromEnv() Config {
	authBase := envOr("PQT_AUTH_BASE_URL", "http://localhost:8080")
	return Config{
		Addr:                envOr("PQT_RESOURCE_ADDR", ":8081"),
		AuthServerBaseURL:   authBase,
		ExpectedIssuer:      envOr("PQT_RESOURCE_ISSUER", authBase),
		ExpectedAudience:    envOr("PQT_RESOURCE_AUDIENCE", ""),
		Leeway:              envDuration("PQT_RESOURCE_LEEWAY", 0),
		JWKSRefreshInterval: envDuration("PQT_RESOURCE_JWKS_REFRESH", 5*time.Minute),
		HTTPTimeout:         envDuration("PQT_RESOURCE_HTTP_TIMEOUT", 5*time.Second),
	}
}

func (c *Config) validate() error {
	if c.Addr == "" {
		c.Addr = ":8081"
	}
	if c.AuthServerBaseURL == "" {
		c.AuthServerBaseURL = "http://localhost:8080"
	}
	if c.ExpectedIssuer == "" {
		c.ExpectedIssuer = c.AuthServerBaseURL
	}
	if c.JWKSRefreshInterval <= 0 {
		c.JWKSRefreshInterval = 5 * time.Minute
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 5 * time.Second
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
