package bench_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
	"golang.org/x/crypto/bcrypt"

	"pqt/internal/authserver"
	"pqt/internal/resourceserver"
	"pqt/keys"
)

// loadEnv — пара поднятых через httptest сервисов: auth и resource.
// Используется обоими smoke-тестами нагрузки.
type loadEnv struct {
	authURL string
	resURL  string
}

// startLoadEnv поднимает auth-сервер и resource-сервер, отдаёт их URL.
// bcrypt MinCost — иначе smoke упирается в хэширование, а не в нагрузку.
func startLoadEnv(t *testing.T) loadEnv {
	t.Helper()
	silent := slog.New(slog.NewTextHandler(io.Discard, nil))

	authSrv, err := authserver.New(authserver.Config{
		Issuer:      "http://test-auth",
		KeysDir:     t.TempDir(),
		AccessTTL:   15 * time.Minute,
		GenerateAlg: keys.AlgECDSAP256,
		BcryptCost:  bcrypt.MinCost,
		Logger:      silent,
	})
	if err != nil {
		t.Fatalf("authserver.New: %v", err)
	}
	authHTTP := httptest.NewServer(authSrv.Handler())
	t.Cleanup(authHTTP.Close)

	resSrv, err := resourceserver.New(resourceserver.Config{
		AuthServerBaseURL: authHTTP.URL,
		ExpectedIssuer:    authSrv.Issuer(),
		ExpectedAudience:  authSrv.Issuer(),
		Logger:            silent,
	})
	if err != nil {
		t.Fatalf("resourceserver.New: %v", err)
	}
	resHTTP := httptest.NewServer(resSrv.Handler())
	t.Cleanup(resHTTP.Close)

	return loadEnv{authURL: authHTTP.URL, resURL: resHTTP.URL}
}

// TestLoadSmoke_Token — короткий smoke-тест нагрузки на /auth/token.
//
// Запускает реальный auth-сервер через httptest и бьёт по нему vegeta'й
// 50 RPS × 1 секунда. Цель не научный замер, а проверка что:
//   - сценарий нагрузочного теста собирается и работает;
//   - сервер не разваливается под одновременными запросами.
//
// Для главы 4.6 диссертации используется не этот тест, а отдельная команда
// pqt-loadtest, которую запускают против отдельно стоящего сервера.
func TestLoadSmoke_Token(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke-нагрузка пропущена в коротком прогоне")
	}

	env := startLoadEnv(t)

	body := url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"alice-password-2026"},
	}.Encode()

	target := vegeta.Target{
		Method: http.MethodPost,
		URL:    env.authURL + "/auth/token",
		Body:   []byte(body),
		Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
	}

	metrics := runShortAttack(vegeta.NewStaticTargeter(target), 50, time.Second)

	if metrics.Success < 0.99 {
		t.Fatalf("success rate = %.2f%%, ожидали ≥99%%", metrics.Success*100)
	}
	if metrics.Requests == 0 {
		t.Fatal("vegeta не выпустила ни одного запроса")
	}
	t.Logf("token: %d req @ %.0f req/s, p95=%v, success=%.2f%%",
		metrics.Requests, metrics.Rate, metrics.Latencies.P95, metrics.Success*100)
}

// TestLoadSmoke_Me — smoke-тест нагрузки на /me. Логинится в auth-сервер,
// получает access-токен, потом 50 RPS × 1 секунда бьёт GET /me на
// resource-сервере с этим токеном. Проверяет, что resource-сервер вместе
// с JWKS-кэшем выдерживает простую параллельную нагрузку.
func TestLoadSmoke_Me(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke-нагрузка пропущена в коротком прогоне")
	}

	env := startLoadEnv(t)
	access := loginForLoad(t, env.authURL)

	target := vegeta.Target{
		Method: http.MethodGet,
		URL:    env.resURL + "/me",
		Header: http.Header{"Authorization": []string{"Bearer " + access}},
	}

	metrics := runShortAttack(vegeta.NewStaticTargeter(target), 50, time.Second)

	if metrics.Success < 0.99 {
		t.Fatalf("success rate = %.2f%%, ожидали ≥99%%", metrics.Success*100)
	}
	if metrics.Requests == 0 {
		t.Fatal("vegeta не выпустила ни одного запроса")
	}
	t.Logf("me: %d req @ %.0f req/s, p95=%v, success=%.2f%%",
		metrics.Requests, metrics.Rate, metrics.Latencies.P95, metrics.Success*100)
}

func loginForLoad(t *testing.T, baseURL string) string {
	t.Helper()
	body := url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"alice-password-2026"},
	}.Encode()

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, baseURL+"/auth/token", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return out.AccessToken
}

// runShortAttack гонит vegeta короткое время с фиксированной скоростью и
// возвращает собранную метрику.
func runShortAttack(targeter vegeta.Targeter, rps int, dur time.Duration) *vegeta.Metrics {
	rate := vegeta.Rate{Freq: rps, Per: time.Second}
	attacker := vegeta.NewAttacker(vegeta.Timeout(5 * time.Second))

	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, dur, "smoke") {
		metrics.Add(res)
	}
	metrics.Close()
	return &metrics
}
