package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/twig/twig-cloud/internal/api"
	"github.com/twig/twig-cloud/internal/auth"
	"github.com/twig/twig-cloud/internal/config"
	"github.com/twig/twig-cloud/internal/database"
)

const (
	shutdownTimeout = 10 * time.Second
	dbFileName      = "twig.db"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbPath := filepath.Join(cfg.DataDir, dbFileName)
	db, err := database.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	// Runs when run returns, i.e. after srv.Shutdown has drained requests.
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("close database", "error", err)
			return
		}
		logger.Info("database closed")
	}()

	applied, err := db.Migrate(ctx)
	if err != nil {
		return err
	}
	logger.Info("database ready", "path", dbPath, "migrations_applied", applied)

	authSvc, err := auth.NewService(db, auth.Options{
		AccessTTL:  cfg.AccessTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL,
		Logger:     logger,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           api.NewHandler(authSvc, logger),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server listening", "addr", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		logger.Info("shutdown complete")
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
