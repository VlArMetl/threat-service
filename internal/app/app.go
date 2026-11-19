package app

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"time"

	"threat-service/internal/handler"
	"threat-service/internal/middleware"
	"threat-service/internal/storage"
)

func NewHTTPHandler(cfg Config, store storage.Storage) http.Handler {
	h := handler.New(store).Routes()
	if cfg.AuthEnabled() {
		h = middleware.APIKeyAuth(cfg.ReadAPIKeys, cfg.WriteAPIKeys)(h)
	}
	return middleware.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst).Middleware(h)
}

func Run(ctx context.Context, cfg Config) error {
	store, closeStore, err := newStorage(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	if !cfg.AuthEnabled() {
		log.Println("API_KEYS и READ_API_KEYS не заданы, авторизация отключена")
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           NewHTTPHandler(cfg, store),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			log.Printf("Запуск сервера на %s (HTTPS)", cfg.Addr)
			errCh <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			log.Printf("Запуск сервера на %s (HTTP)", cfg.Addr)
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	log.Println("Остановка сервера")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func newStorage(ctx context.Context, cfg Config) (storage.Storage, func(), error) {
	if cfg.DatabaseURL == "" {
		log.Println("DATABASE_URL не задан, данные хранятся в памяти")
		return storage.NewMemoryStorage(), func() {}, nil
	}

	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pg, err := storage.NewPostgresStorage(connectCtx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Подключение к PostgreSQL установлено")
	return pg, pg.Close, nil
}
