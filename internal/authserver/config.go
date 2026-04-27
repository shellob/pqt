// Package authserver — это сервер авторизации PQ-AT для прототипа
// диссертации. Снаружи он выглядит как обычный OAuth 2.0-сервер: умеет
// выдавать токены по логину-паролю, обновлять их по refresh-токену,
// отзывать и публиковать свои публичные ключи в виде JWKS. Внутри —
// тонкая обвязка над библиотекой pqt: вся криптография и формат
// токена там, здесь только HTTP-эндпоинты, хранилища (in-memory) и
// проверка пользователей.
//
// Сервер реализует только тот набор возможностей, который нужен
// прототипу для главы 4 диссертации:
//
//   - POST /auth/token — выдача access + refresh пары по логину
//     и паролю (grant_type=password, упрощённый flow для эксперимента);
//   - POST /auth/refresh — обновление access по refresh, со сменой
//     refresh-токена (rotation);
//   - POST /auth/revoke — отзыв токена (RFC 7009);
//   - GET /.well-known/pq-jwks — публичные ключи сервера в виде JWKS;
//   - GET /.well-known/oauth-authorization-server — OAuth-метаданные
//     сервера (RFC 8414);
//   - GET /debug/pprof/* — стандартный профайлер Go (только при
//     включённом флаге --debug или PQT_DEBUG=1);
//   - GET / + /static/* + /docs/* — встроенный демо-UI и Swagger UI.
//
// Persistance, multi-tenancy, настоящая база пользователей, OAuth client
// credentials и т. д. — за рамками прототипа.
package authserver

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pqt/keys"
)

// Config — все параметры запуска сервера, собранные в одну структуру.
//
// На практике пользователь меняет их через переменные окружения (см.
// LoadFromEnv ниже); программно структура заполняется в основном в
// тестах, чтобы можно было запустить сервер in-memory с нужными
// настройками — например, с минимальной стоимостью bcrypt и
// фиксированным временем.
type Config struct {
	// Addr — на каком интерфейсе и порту слушает HTTP-сервер. Формат
	// тот же, что у net.Listen ("host:port" или ":port"). По
	// умолчанию ":8080" — слушать все интерфейсы на 8080-м порту.
	Addr string

	// Issuer — URL, который попадёт в claim iss выдаваемых токенов.
	// Это идентификатор данного сервера авторизации; клиенты-валидаторы
	// сверяют его с ExpectedIssuer и должны видеть совпадение.
	// По умолчанию "http://localhost:8080".
	Issuer string

	// KeysDir — директория, где сервер хранит свои приватные ключи в
	// формате JWK. На каждый ключ — пара файлов: <kid>.priv.jwk.json
	// и <kid>.pub.jwk.json.
	//
	// Поведение при старте:
	//   - если в директории есть файлы *.priv.jwk.json — все они
	//     загружаются;
	//   - если директории нет или она пустая, сервер генерирует один
	//     ключ алгоритма GenerateAlg, кладёт его сюда и продолжает.
	//
	// По умолчанию "./keys".
	KeysDir string

	// DefaultKid — kid того ключа, которым сервер подписывает новые
	// токены. Должен совпадать с одним из загруженных. Если поле
	// пустое, выбирается первый по алфавитной сортировке kid из
	// загруженного набора (детерминированно — чтобы при перезапусках
	// был тот же выбор).
	DefaultKid string

	// AccessTTL — сколько живёт access-токен после выдачи. По
	// умолчанию 15 минут — стандартный для OAuth короткий срок,
	// чтобы кража токена не давала вечного доступа.
	AccessTTL time.Duration

	// RefreshTTL — сколько живёт refresh-токен. Refresh нужен, чтобы
	// получать новые access без повторного ввода пароля. По умолчанию
	// 30 дней; refresh всегда длиннее access на порядки.
	RefreshTTL time.Duration

	// GenerateAlg — каким алгоритмом сгенерировать ключ при первом
	// старте, когда в KeysDir пусто. По умолчанию hybrid-ecdsa-mldsa65
	// (целевой режим спецификации PQ-AT). Если в директории уже лежит
	// ключ — это поле игнорируется, используется он.
	GenerateAlg keys.Alg

	// BcryptCost — параметр сложности bcrypt при хешировании паролей
	// seed-пользователей на старте сервера. Значение от bcrypt.MinCost
	// (4) до bcrypt.MaxCost (31); чем больше — тем дольше каждая
	// проверка пароля и тем труднее подобрать пароль перебором.
	//
	// По умолчанию bcrypt.DefaultCost (10) — это около 60 миллисекунд
	// проверки на современном CPU. В тестах cost обычно ставят на
	// MinCost (4), иначе старт каждого тестового сервера занимал бы
	// секунды на хеширование четырёх seed-юзеров.
	BcryptCost int

	// Debug включает диагностические эндпоинты /debug/pprof/* —
	// стандартный профайлер Go, через него снимают CPU-профиль, дамп
	// кучи, список горутин. По умолчанию выключено: эти эндпоинты
	// раскрывают внутреннее состояние сервера и в production-сервисе
	// доступ к ним должен быть закрыт (отдельным портом, авторизацией,
	// IP-фильтром). Включается флагом --debug у бинаря или env
	// PQT_DEBUG=1.
	Debug bool

	// Logger — куда писать диагностические сообщения. Если nil,
	// используется slog.Default() — обычно туда попадает stderr.
	Logger *slog.Logger

	// Now — функция, возвращающая текущее время. Используется при
	// выпуске токенов (в claims iat/exp) и при проверке refresh.
	// Если nil, берётся time.Now. В тестах сюда обычно подставляется
	// функция, возвращающая фиксированный момент — это даёт
	// воспроизводимое поведение и позволяет проверять граничные
	// случаи срока действия токенов.
	Now func() time.Time
}

// LoadFromEnv читает конфиг из переменных окружения, подставляя
// разумные значения по умолчанию для отсутствующих переменных.
//
// Какие переменные распознаются:
//
//	PQT_ADDR           — адрес для Listen, например ":8080".
//	PQT_ISSUER         — URL, попадающий в claim iss.
//	PQT_KEYS_DIR       — директория с приватными JWK-файлами.
//	PQT_DEFAULT_KID    — kid ключа для подписи новых токенов.
//	PQT_ACCESS_TTL     — сколько живёт access (формат time.ParseDuration: "15m").
//	PQT_REFRESH_TTL    — сколько живёт refresh.
//	PQT_GENERATE_ALG   — алгоритм для авто-генерации ключа.
//	PQT_BCRYPT_COST    — параметр сложности bcrypt (от 4 до 31).
//	PQT_DEBUG          — 1/true/yes/on, чтобы включить /debug/pprof/*.
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
		Debug:       envBool("PQT_DEBUG", false),
	}
}

// validate подставляет значения по умолчанию для пустых полей и
// проверяет, что итоговая конфигурация осмысленна. Возвращает ошибку,
// если по содержимому полей запустить сервер невозможно (например,
// неизвестный алгоритм или cost вне допустимого диапазона).
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

// envOr берёт переменную окружения по имени; если она пустая или не
// задана — возвращает fallback.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envDuration читает переменную как time.Duration ("15m", "1h30m" и т. п.).
// Если переменной нет или формат неправильный — возвращается fallback,
// без ошибки в лог: для прототипа это нормально, в production стоило бы
// явно говорить пользователю «вы передали мусор».
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

// envInt читает переменную как целое число. Поведение при ошибке
// разбора такое же, как у envDuration — fallback.
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

// envBool читает переменную как булев флаг. Истинными считаются
// "1", "true", "yes", "on" в любом регистре; всё остальное — false.
// Если переменная не задана — возвращается fallback.
func envBool(name string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
