// Команда pqt-resource — запускаемый бинарник демо-сервера ресурсов.
// Сам по себе резерв-сервер — это любой сервис, который отдаёт что-то
// защищённое и хочет проверить, что у клиента есть валидный access-токен.
// Этот бинарник показывает, как такой сервис должен использовать
// библиотеки pqt и pqt/jwk для самостоятельной проверки токенов,
// выпущенных pqt-authserver — никакого общения с auth-сервером по
// каждому запросу не нужно, достаточно периодически тянуть с него JWKS.
//
// Реализованы два эндпоинта:
//
//	GET /me     — вернёт claims текущего пользователя (sub, scope и т. д.).
//	             Полезно, чтобы убедиться, что токен принят и сервер видит
//	             правильную личность.
//	GET /admin  — то же, но дополнительно требует, чтобы в claim scope
//	             была запись "admin". Без неё — 403.
//
// Поведение настраивается переменными окружения (resourceserver.LoadFromEnv).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pqt/internal/resourceserver"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg := resourceserver.LoadFromEnv()
	cfg.Logger = logger

	srv, err := resourceserver.New(cfg)
	if err != nil {
		logger.Error("создание сервера", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	listenErr := make(chan error, 1)
	go func() {
		logger.Info("запускаю listener", "addr", cfg.Addr, "auth_server", cfg.AuthServerBaseURL)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
		}
		close(listenErr)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		logger.Info("получен сигнал, останавливаемся", "signal", sig.String())
	case err := <-listenErr:
		logger.Error("ListenAndServe", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown", "err", err)
		os.Exit(1)
	}
	logger.Info("сервер остановлен")
}
