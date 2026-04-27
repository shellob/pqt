package resourceserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"pqt/jwk"
	"pqt/keys"
	"pqt/token"
)

// JWKSClient скачивает jwk.Set с auth-сервера, держит его в кэше и
// отдаёт публичный ключ по kid.
//
// Логика KeyByKid:
//  1. Ключ есть в кэше — возвращаем сразу.
//  2. Ключа нет — делаем принудительный fetch с auth-сервера и пробуем
//     ещё раз. Если по-прежнему не нашли — возвращаем ошибку, и внешний
//     слой (pqt.Validate) превращает её в ErrKeyNotFound.
//
// Эта простая схема покрывает ротацию ключей без отдельного механизма
// инвалидации кэша: новый kid появляется в JWKS на стороне auth-сервера,
// первый же токен под ним промахивается мимо кэша, клиент сам тянет
// свежий JWKS — и дальше всё работает.
type JWKSClient struct {
	baseURL string
	httpC   *http.Client
	logger  jwksLogger

	mu          sync.RWMutex
	keysByKid   map[string]keys.PublicKey
	lastRefresh time.Time
}

// jwksLogger — минимальный интерфейс для логгирования внутри клиента.
// slog.Logger его удовлетворяет; можно подсунуть и пустой no-op для тестов.
type jwksLogger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NewJWKSClient создаёт клиент, привязанный к baseURL auth-сервера.
// httpClient может быть nil — тогда используется http.DefaultClient с
// заданным timeout.
func NewJWKSClient(baseURL string, httpClient *http.Client, logger jwksLogger) *JWKSClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &JWKSClient{
		baseURL:   baseURL,
		httpC:     httpClient,
		logger:    logger,
		keysByKid: make(map[string]keys.PublicKey),
	}
}

// KeyByKid реализует pqt.KeySource в одной из распространённых форм:
// принимает заголовок токена и возвращает публичный ключ для проверки подписи.
func (c *JWKSClient) KeyByKid(h token.Header) (keys.PublicKey, error) {
	if pub := c.lookup(h.Kid); pub != nil {
		return pub, nil
	}

	// Cache miss — пытаемся обновить набор. Если обновление не удалось,
	// возвращаем понятную ошибку: внешний слой (Validate) вернёт ErrKeyNotFound.
	if err := c.Refresh(context.Background()); err != nil {
		c.logger.Error("resourceserver: обновление JWKS на cache-miss", "err", err, "kid", h.Kid)
	}

	if pub := c.lookup(h.Kid); pub != nil {
		return pub, nil
	}
	return nil, fmt.Errorf("kid %q не найден в JWKS", h.Kid)
}

// Refresh скачивает JWKS с auth-сервера и пересобирает кеш ключей.
// Безопасно вызывать конкурентно; блокирует mutex только на время записи.
func (c *JWKSClient) Refresh(ctx context.Context) error {
	url := c.baseURL + "/.well-known/pq-jwks"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("resourceserver: построение запроса JWKS: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return fmt.Errorf("resourceserver: запрос JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("resourceserver: JWKS вернул статус %d", resp.StatusCode)
	}

	var set jwk.Set
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("resourceserver: разбор JWKS: %w", err)
	}

	parsed := make(map[string]keys.PublicKey, len(set.Keys))
	for _, j := range set.Keys {
		if j.Kid == "" {
			c.logger.Warn("resourceserver: пропускаю ключ без kid в JWKS")
			continue
		}
		pub, err := jwk.ParsePublic(j)
		if err != nil {
			c.logger.Warn("resourceserver: пропускаю битый ключ из JWKS", "kid", j.Kid, "err", err)
			continue
		}
		parsed[j.Kid] = pub
	}

	c.mu.Lock()
	c.keysByKid = parsed
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *JWKSClient) lookup(kid string) keys.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keysByKid[kid]
}
