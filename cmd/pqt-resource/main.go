// Команда pqt-resource — демо-сервер ресурсов PQ-AT.
//
// Это пример того, как внешний сервис должен использовать pqt + jwk для
// проверки токенов, выпущенных pqt-authserver. Реализует два эндпоинта:
//
//	GET /me    — возвращает claims текущего пользователя.
//	GET /admin — то же, но требует scope=admin.
//
// Поведение настраивается переменными окружения (см. resourceserver.LoadFromEnv).
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
