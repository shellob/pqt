// Команда pqt-loadtest бьёт нагрузкой по уже запущенному pqt-authserver
// через github.com/tsenart/vegeta. Используется для замеров главы 4.6
// диссертации: throughput, latency-распределение, поведение под предельной
// нагрузкой.
//
// Подразумевается, что auth-сервер запущен отдельно — это ближе к реальной
// картине сети, чем in-process нагрузка через httptest. Если на сервере
// нужен профиль — параллельно запустить:
//
//	go tool pprof -http=:6060 http://localhost:8080/debug/pprof/profile?seconds=30
//
// Сервер должен быть стартован с флагом --debug или PQT_DEBUG=1.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	scenarioToken = "token"
	scenarioMe    = "me"
)

type config struct {
	scenario string
	authBase string
	resBase  string
	rate     int
	duration time.Duration
	username string
	password string
	httpC    *http.Client
}

func main() {
	cfg := parseFlags()

	switch cfg.scenario {
	case scenarioToken:
		runTokenScenario(cfg)
	case scenarioMe:
		runMeScenario(cfg)
	default:
		fatalf("неизвестный сценарий %q (допустимо %q или %q)",
			cfg.scenario, scenarioToken, scenarioMe)
	}
}

func parseFlags() config {
	c := config{httpC: &http.Client{Timeout: 10 * time.Second}}

	flag.StringVar(&c.scenario, "scenario", scenarioToken,
		"что грузим: token (POST /auth/token) или me (логин + GET /me)")
	flag.StringVar(&c.authBase, "auth", "http://localhost:8080",
		"базовый URL pqt-authserver")
	flag.StringVar(&c.resBase, "resource", "http://localhost:8081",
		"базовый URL pqt-resource (только для сценария me)")
	flag.IntVar(&c.rate, "rate", 100, "запросов в секунду")
	flag.DurationVar(&c.duration, "duration", 30*time.Second, "длительность атаки")
	flag.StringVar(&c.username, "username", "alice", "seed-логин")
	flag.StringVar(&c.password, "password", "alice-password-2026", "seed-пароль")

	flag.Parse()

	if c.rate <= 0 {
		fatalf("--rate должен быть > 0, получили %d", c.rate)
	}
	if c.duration <= 0 {
		fatalf("--duration должна быть > 0, получили %s", c.duration)
	}

	return c
}

// runTokenScenario бьёт POST /auth/token с одинаковым логином и паролем.
// Этот сценарий нагружает основной hot-path выпуска токенов: bcrypt-проверку
// пароля + подпись.
func runTokenScenario(cfg config) {
	body := url.Values{
		"grant_type": {"password"},
		"username":   {cfg.username},
		"password":   {cfg.password},
	}.Encode()

	target := vegeta.Target{
		Method: http.MethodPost,
		URL:    cfg.authBase + "/auth/token",
		Body:   []byte(body),
		Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
	}

	runAttack(cfg, "token (POST /auth/token)", target.URL, vegeta.NewStaticTargeter(target))
}

// runMeScenario сначала разово логинится и получает access-токен, потом
// бьёт GET /me на resource-сервере с этим токеном в заголовке Authorization.
// Этот сценарий нагружает hot-path проверки токена: разбор формата + verify
// подписи + опциональный JWKS-кэш.
func runMeScenario(cfg config) {
	access, err := login(cfg)
	if err != nil {
		fatalf("логин не удался: %v", err)
	}

	target := vegeta.Target{
		Method: http.MethodGet,
		URL:    cfg.resBase + "/me",
		Header: http.Header{"Authorization": []string{"Bearer " + access}},
	}

	runAttack(cfg, "me (GET /me)", target.URL, vegeta.NewStaticTargeter(target))
}

// login вызывает POST /auth/token и возвращает access-токен. Используется
// сценарием me как однократный setup перед нагрузкой.
func login(cfg config) (string, error) {
	body := url.Values{
		"grant_type": {"password"},
		"username":   {cfg.username},
		"password":   {cfg.password},
	}.Encode()

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, cfg.authBase+"/auth/token", strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("сборка запроса: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cfg.httpC.Do(req)
	if err != nil {
		return "", fmt.Errorf("запрос: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("статус %d, ожидали 200", resp.StatusCode)
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("разбор ответа: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("сервер вернул пустой access_token")
	}
	return out.AccessToken, nil
}

// runAttack крутит атаку и печатает итоговый отчёт. Каждый ответ собирается
// в Metrics; в конце печатаем сводку (Requests, Throughput, Latencies p50/p95/p99,
// Success ratio + распределение статус-кодов).
func runAttack(cfg config, label, targetURL string, targeter vegeta.Targeter) {
	rate := vegeta.Rate{Freq: cfg.rate, Per: time.Second}
	attacker := vegeta.NewAttacker()

	fmt.Fprintf(os.Stderr, "грузим %s: %d req/s × %s → %s\n",
		label, cfg.rate, cfg.duration, targetURL)

	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, cfg.duration, label) {
		metrics.Add(res)
	}
	metrics.Close()

	// Ошибку записи в stdout игнорируем сознательно: к этому моменту часть
	// отчёта уже могла быть напечатана, и вернуть «частичный успех с ошибкой»
	// через fatal — только запутывать вывод.
	_ = vegeta.NewTextReporter(&metrics).Report(os.Stdout)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pqt-loadtest: "+format+"\n", args...)
	os.Exit(1)
}
