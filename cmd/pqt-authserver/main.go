// Команда pqt-authserver — сервер авторизации PQ-AT.
//
// Это прототип для главы 3 диссертации и стенд для эксперимента главы 4.
// Запуск:
//
//	pqt-authserver
//
// Поведение настраивается переменными окружения (см. internal/authserver/Config.LoadFromEnv).
// При первом запуске, если PQT_KEYS_DIR пустой или не существует, сервер
// автоматически генерирует свежий ключ и сохраняет его туда.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pqt/internal/authserver"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	debug := flag.Bool("debug", false,
		"включить /debug/pprof/* (профилирование). Эквивалент PQT_DEBUG=1.")
	flag.Parse()

	cfg := authserver.LoadFromEnv()
	cfg.Logger = logger
	if *debug {
		cfg.Debug = true
	}

	srv, err := authserver.New(cfg)
	if err != nil {
		logger.Error("создание сервера", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Слушаем в фоне; об ошибках Listen сообщаем через отдельный канал,
	// чтобы main мог корректно дождаться либо ошибки, либо сигнала.
	listenErr := make(chan error, 1)
	go func() {
		logger.Info("запускаю listener", "addr", cfg.Addr, "issuer", cfg.Issuer)
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
