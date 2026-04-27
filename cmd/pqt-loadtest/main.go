// Команда pqt-loadtest нагружает уже запущенный pqt-authserver (а в одном
// из сценариев — и pqt-resource) синтетическими HTTP-запросами через
// библиотеку vegeta. Этим инструментом снимаются цифры для главы 4.6
// диссертации: сколько запросов в секунду сервер выдерживает, какое у него
// распределение времени отклика (медиана, 95-я и 99-я перцентили), как
// он ведёт себя при перегрузе.
//
// Сервер мы стартуем отдельным процессом, а не через httptest внутри
// бенчмарка. Внешний запуск ближе к реальной картине: в стек попадают
// настоящий TCP-loopback, ядро ОС и сетевой буфер — то, чего нет при
// in-process тестировании. Цифры из in-process бенчмарков в главе 4.3
// меряют только саму библиотеку, а тут мерим всё в сборе.
//
// Параллельно с нагрузкой удобно снимать профиль через pprof, чтобы
// потом понять, на чём именно сервер тратит время:
//
//	go tool pprof -http=:6060 http://localhost:8080/debug/pprof/profile?seconds=30
//
// Для этого pqt-authserver нужно стартовать с флагом --debug (или
// переменной PQT_DEBUG=1) — иначе эндпоинты /debug/pprof/* выключены.
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

// runTokenScenario гонит на сервер один и тот же POST /auth/token раз за
// разом с фиксированными логином и паролем. Этот сценарий проверяет
// тяжёлый путь выпуска токена: проверка пароля через bcrypt (десятки
// миллисекунд при cost=10) плюс собственно подпись токена приватным
// ключом. На этой нагрузке узкое место сервера — именно bcrypt.
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

// runMeScenario сначала разово логинится через POST /auth/token, забирает
// один access-токен, и затем шлёт с ним подряд много запросов GET /me на
// resource-сервер. Этот сценарий проверяет другую часть стека — путь
// проверки токена: разобрать формат, найти ключ в JWKS-кэше, проверить
// подпись и стандартные claims. Здесь bcrypt не работает (логин был один
// в самом начале), и видно, как быстро сервер отвечает на чистой
// криптопроверке подписи.
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

// login один раз стучится на POST /auth/token, забирает access-токен и
// возвращает его строкой. Сценарий me использует это перед запуском
// нагрузки: получили один токен, дальше с ним бомбим resource-сервер.
// Сам логин в нагрузке не участвует и в метрики не попадает.
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

// runAttack запускает саму нагрузку и печатает итоговый отчёт. Под капотом
// это выглядит так: vegeta создаёт нужный поток запросов с заданной
// частотой (rate × per second), отправляет их параллельно, для каждого
// собирает время отклика и код ответа. Все эти результаты собираются в
// vegeta.Metrics; после атаки выводится сводка: общее число запросов,
// фактическая пропускная способность (Throughput), время отклика по
// 50-й/95-й/99-й перцентилям, доля успешных ответов и распределение
// статус-кодов.
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

	// Ошибку записи отчёта в stdout игнорируем намеренно. К этому моменту
	// часть отчёта могла быть уже напечатана (например, пайп закрылся
	// после прочтения первых строк через head), и завершать программу
	// через os.Exit(1) с сообщением «не удалось записать отчёт» было бы
	// странно — пользователь видит правильные цифры в начале, а потом
	// «ошибку», как будто что-то сломалось. Лучше тихо закончить.
	_ = vegeta.NewTextReporter(&metrics).Report(os.Stdout)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pqt-loadtest: "+format+"\n", args...)
	os.Exit(1)
}
