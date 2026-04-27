// Команда pqt-authserver — это запускаемый бинарник OAuth-сервера авторизации,
// поверх библиотеки pqt. Сама логика и эндпоинты живут в пакете
// internal/authserver; этот файл — только запуск.
//
// Используется как прототип для главы 3 диссертации (где описывается
// архитектура) и как стенд для эксперимента главы 4 (где гоняются
// бенчмарки). Поэтому здесь подчёркнуто скромный набор: настройки —
// через переменные окружения (см. authserver.Config.LoadFromEnv), без
// конфиг-файлов и сложного CLI.
//
// Запуск:
//
//	pqt-authserver              # боевой режим
//	pqt-authserver --debug      # дополнительно включает /debug/pprof
//
// При первом запуске, если каталог из переменной PQT_KEYS_DIR не существует
// или в нём нет ключей, сервер сам сгенерирует свежий ключ и сохранит туда.
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

	// http.Server.ListenAndServe — блокирующий вызов: пока сервер работает,
	// он из него не возвращается. Поэтому запускаем его в отдельной горутине,
	// а ошибку (если порт занят, или конфигурация не валидна) кладём в канал.
	// В main ниже через select мы одновременно ждём двух событий: сигнал
	// от ОС на завершение или ошибку от listener'а — что наступит первым.
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
