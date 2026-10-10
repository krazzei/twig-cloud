// Package config loads server configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

const (
	EnvPort            = "PORT"
	EnvDataDir         = "DATA_DIR"
	EnvAccessTokenTTL  = "ACCESS_TOKEN_TTL"
	EnvRefreshTokenTTL = "REFRESH_TOKEN_TTL"
	EnvPartSize        = "PART_SIZE"
	EnvQuotaBytes      = "QUOTA_BYTES"
	EnvLogLevel        = "LOG_LEVEL"

	DefaultPort            = 8080
	DefaultDataDir         = "./data"
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	DefaultPartSize        = 8 * 1024 * 1024

	MinPartSize = 64 * 1024
	MaxPartSize = 256 * 1024 * 1024
)

type Config struct {
	Port            int
	DataDir         string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	PartSize        int64
	QuotaBytes      int64 // 0 = unlimited
	LogLevel        slog.Level
}

func Load() (*Config, error) {
	return load(os.Getenv)
}

func load(getenv func(string) string) (*Config, error) {
	cfg := &Config{
		Port:            DefaultPort,
		DataDir:         DefaultDataDir,
		AccessTokenTTL:  DefaultAccessTokenTTL,
		RefreshTokenTTL: DefaultRefreshTokenTTL,
		PartSize:        DefaultPartSize,
		QuotaBytes:      0,
		LogLevel:        slog.LevelInfo,
	}

	if v := getenv(EnvPort); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not an integer", EnvPort, v)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("%s: %d out of range 1-65535", EnvPort, n)
		}
		cfg.Port = n
	}

	if v := getenv(EnvDataDir); v != "" {
		cfg.DataDir = v
	} else if cfg.DataDir == "" {
		return nil, errors.New("data dir must not be empty")
	}

	if v := getenv(EnvAccessTokenTTL); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvAccessTokenTTL, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("%s: must be positive", EnvAccessTokenTTL)
		}
		cfg.AccessTokenTTL = d
	}

	if v := getenv(EnvRefreshTokenTTL); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvRefreshTokenTTL, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("%s: must be positive", EnvRefreshTokenTTL)
		}
		cfg.RefreshTokenTTL = d
	}

	if v := getenv(EnvPartSize); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not an integer", EnvPartSize, v)
		}
		if n < MinPartSize || n > MaxPartSize {
			return nil, fmt.Errorf("%s: %d out of range %d-%d", EnvPartSize, n, MinPartSize, MaxPartSize)
		}
		cfg.PartSize = n
	}

	if v := getenv(EnvQuotaBytes); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not an integer", EnvQuotaBytes, v)
		}
		if n < 0 {
			return nil, fmt.Errorf("%s: must be >= 0 (0 = unlimited)", EnvQuotaBytes)
		}
		cfg.QuotaBytes = n
	}

	if v := getenv(EnvLogLevel); v != "" {
		var lvl slog.Level
		if err := lvl.UnmarshalText([]byte(v)); err != nil {
			return nil, fmt.Errorf("%s: %q: %w", EnvLogLevel, v, err)
		}
		cfg.LogLevel = lvl
	}

	return cfg, nil
}
