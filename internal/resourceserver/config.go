// Package resourceserver — пример сервера ресурсов, защищённого PQ-AT-токенами.
//
// В терминах OAuth 2.0 «сервер ресурсов» — это сервис, который отдаёт что-то
// полезное (профиль пользователя, файлы, данные) и хочет убедиться, что
// клиент имеет право это получить. Сам он токены не выпускает — этим
// занимается auth-сервер; resource-сервер только проверяет приходящий
// access-токен и пускает запрос дальше, если подпись и claims в порядке.
//
// Реальная работа сосредоточена в трёх местах:
//
//   - jwks_client.go — фоном скачивает с auth-сервера набор публичных ключей
//     (JWKS), чтобы было чем проверять подписи токенов;
//   - middleware.go — HTTP-обёртка, которая на каждый запрос разбирает
//     заголовок Authorization, валидирует токен через pqt.Validate
//     и кладёт claims в контекст;
//   - server.go — маршруты /me и /admin, которые читают claims из контекста.
//
// Никакой собственной криптографии здесь нет — для проверки используются те
// же pqt.Validate и jwk.Set, что доступны любому стороннему пользователю
// библиотеки. Это намеренно: показать, что для интеграции с PQ-AT
// достаточно публичного API, ничего внутреннего знать не нужно.
package resourceserver

import (
	"log/slog"
	"os"
	"time"
)

// Config — параметры запуска resource-сервера. Заполняется в main или в
// тестах перед вызовом New; пустое значение поля заменяется на разумное
// дефолтное в методе validate.
type Config struct {
	// Addr — на каком адресе и порту слушать HTTP-запросы. Формат — как у
	// http.ListenAndServe: ":8081" — слушать на всех интерфейсах,
	// "127.0.0.1:8081" — только на локальном. По умолчанию ":8081".
	Addr string

	// AuthServerBaseURL — базовый URL auth-сервера, у которого resource-сервер
	// скачивает набор публичных ключей (JWKS). Без этого нечем проверять
	// подписи токенов. Например, "http://localhost:8080" — тогда JWKS
	// тянется из "http://localhost:8080/.well-known/pq-jwks".
	AuthServerBaseURL string

	// ExpectedIssuer — значение, которое должно стоять в claim "iss" у
	// каждого входящего токена. Если в токене другой издатель — токен
	// отвергается. По умолчанию совпадает с AuthServerBaseURL.
	ExpectedIssuer string

	// ExpectedAudience — значение, которое должно стоять в claim "aud":
	// сервис, для которого предназначен токен. Если оставить пустым,
	// проверка aud пропускается — это допустимо для прототипа, но в боевой
	// конфигурации тут должен стоять идентификатор именно этого
	// resource-сервера, иначе чужой токен (выпущенный для другого сервиса
	// тем же auth-сервером) пройдёт проверку.
	ExpectedAudience string

	// Leeway — допустимая разница часов между auth- и resource-серверами.
	// Значение прибавляется к exp при проверке: токен с exp=12:00:00 и
	// leeway=30s считается валидным до 12:00:30. Нужно для случаев, когда
	// часы серверов чуть-чуть разъехались. Слишком большое значение
	// продлевает жизнь украденному токену, поэтому держим коротким.
	Leeway time.Duration

	// JWKSRefreshInterval — как часто фоном перекачивать JWKS, чтобы вовремя
	// подхватить ротацию ключей на auth-сервере. По умолчанию 5 минут:
	// если auth-сервер сменит подписной ключ, новые токены начнут проверяться
	// в течение этих 5 минут (если повезёт, ещё быстрее — клиент умеет сам
	// инициировать обновление при попадании на неизвестный kid).
	JWKSRefreshInterval time.Duration

	// HTTPTimeout — таймаут одного похода в auth-сервер за JWKS. Без него
	// зависший auth-сервер мог бы заблокировать фоновую горутину навсегда.
	// По умолчанию 5 секунд.
	HTTPTimeout time.Duration

	// Logger — куда писать диагностические сообщения. Если nil — используется
	// slog.Default().
	Logger *slog.Logger

	// Now — источник «текущего времени». Подменяется в тестах, чтобы
	// детерминировано проверять поведение около границ exp/iat. В проде —
	// time.Now.
	Now func() time.Time
}

// LoadFromEnv собирает Config, читая значения из переменных окружения.
// Переменные, которые не заданы, остаются пустыми и потом будут заполнены
// дефолтами в методе validate.
//
// Распознаются:
//
//	PQT_RESOURCE_ADDR             — адрес для Listen, например ":8081".
//	PQT_AUTH_BASE_URL             — базовый URL auth-сервера.
//	PQT_RESOURCE_ISSUER           — ожидаемый iss; по умолчанию = PQT_AUTH_BASE_URL.
//	PQT_RESOURCE_AUDIENCE         — ожидаемый aud; по умолчанию пусто (без проверки).
//	PQT_RESOURCE_LEEWAY           — продолжительность вида "30s", по умолчанию 0.
//	PQT_RESOURCE_JWKS_REFRESH     — продолжительность, по умолчанию 5m.
//	PQT_RESOURCE_HTTP_TIMEOUT     — продолжительность, по умолчанию 5s.
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
