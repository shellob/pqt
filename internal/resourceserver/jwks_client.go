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

// JWKSClient скачивает с auth-сервера набор публичных ключей (jwk.Set),
// держит его в памяти и по запросу отдаёт нужный ключ по идентификатору
// kid из заголовка токена.
//
// kid (key id) — это короткая строка, которая прописана в заголовке каждого
// токена и однозначно указывает, каким именно ключом он подписан. На
// auth-сервере одновременно может жить несколько ключей (например, во
// время ротации — старый и новый), и без kid resource-сервер не понял бы,
// какой из них применять.
//
// Алгоритм KeyByKid (см. ниже) собран максимально простым:
//  1. Ключ есть в кэше — возвращаем сразу.
//  2. Ключа нет — делаем внеплановый запрос к auth-серверу и пробуем
//     найти его ещё раз. Если по-прежнему не нашли — возвращаем ошибку,
//     внешний слой (pqt.Validate) превращает её в pqt.ErrKeyNotFound.
//
// Эта схема сама собой покрывает ротацию ключей, без отдельной системы
// сброса кэша. Сценарий: auth-сервер выпустил новый ключ и стал подписывать
// им свежие токены. Первый же токен под новым kid промахивается мимо
// кэша resource-сервера, тот тянет свежий JWKS, кладёт в кэш — и
// последующие токены проверяются уже без сетевого запроса.
type JWKSClient struct {
	baseURL string
	httpC   *http.Client
	logger  jwksLogger

	mu          sync.RWMutex
	keysByKid   map[string]keys.PublicKey
	lastRefresh time.Time
}

// jwksLogger — урезанный интерфейс логгера: только Warn и Error, ничего
// другого изнутри клиента не пишется. *slog.Logger подходит автоматически.
// В тестах удобно подсунуть заглушку с пустыми методами, чтобы вывод не
// замусоривал консоль.
type jwksLogger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NewJWKSClient создаёт клиент, привязанный к baseURL auth-сервера.
// Если httpClient передан как nil, берётся http.DefaultClient — но это
// глобальный клиент без таймаута, поэтому в реальном использовании всегда
// передавайте свой *http.Client с разумным Timeout (см. поле HTTPTimeout
// в Config).
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

// KeyByKid — это и есть точка интеграции с pqt.Validate: подписывается под
// тип pqt.KeySource (берёт заголовок токена, возвращает публичный ключ).
// pqt.Validate вызовет её ровно один раз на каждый проверяемый токен.
func (c *JWKSClient) KeyByKid(h token.Header) (keys.PublicKey, error) {
	if pub := c.lookup(h.Kid); pub != nil {
		return pub, nil
	}

	// Промах мимо кэша. Это нормальная ситуация после ротации ключей на
	// auth-сервере: kid есть в JWKS, но мы его ещё не загрузили. Делаем
	// внеплановый запрос за свежим JWKS и пробуем найти ключ ещё раз.
	// Если запрос упал по сети — логируем и продолжаем: возможно, ключ
	// уже подгрузился фоновой ротацией и lookup ниже всё равно его найдёт.
	if err := c.Refresh(context.Background()); err != nil {
		c.logger.Error("resourceserver: обновление JWKS на cache-miss", "err", err, "kid", h.Kid)
	}

	if pub := c.lookup(h.Kid); pub != nil {
		return pub, nil
	}
	return nil, fmt.Errorf("kid %q не найден в JWKS", h.Kid)
}

// Refresh идёт в auth-сервер за свежим JWKS, разбирает его и заменяет
// текущий кэш ключей новой картой kid→PublicKey. Битые записи (без kid
// или с непонятным форматом ключа) пропускаются с предупреждением — один
// плохой ключ в наборе не должен ронять весь сервер.
//
// Метод безопасно вызывать из нескольких горутин одновременно:
// сетевая часть и разбор работают на локальных переменных, и только на
// финальной замене кэша берётся write-lock мьютекса.
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
