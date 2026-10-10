package config

import (
	"log/slog"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load() error: %v", err)
	}
	if cfg.Port != DefaultPort {
		t.Errorf("Port = %d, want %d", cfg.Port, DefaultPort)
	}
	if cfg.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, DefaultDataDir)
	}
	if cfg.AccessTokenTTL != DefaultAccessTokenTTL {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, DefaultAccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != DefaultRefreshTokenTTL {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, DefaultRefreshTokenTTL)
	}
	if cfg.PartSize != DefaultPartSize {
		t.Errorf("PartSize = %d, want %d", cfg.PartSize, DefaultPartSize)
	}
	if cfg.QuotaBytes != 0 {
		t.Errorf("QuotaBytes = %d, want 0", cfg.QuotaBytes)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := map[string]string{
		EnvPort:            "9090",
		EnvDataDir:         "/srv/twig",
		EnvAccessTokenTTL:  "5m",
		EnvRefreshTokenTTL: "168h",
		EnvPartSize:        "1048576",
		EnvQuotaBytes:      "1073741824",
		EnvLogLevel:        "DEBUG",
	}
	cfg, err := load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("load() error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
	if cfg.DataDir != "/srv/twig" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/srv/twig")
	}
	if cfg.AccessTokenTTL != 5*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want 5m", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 168*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 168h", cfg.RefreshTokenTTL)
	}
	if cfg.PartSize != 1048576 {
		t.Errorf("PartSize = %d, want 1048576", cfg.PartSize)
	}
	if cfg.QuotaBytes != 1073741824 {
		t.Errorf("QuotaBytes = %d, want 1073741824", cfg.QuotaBytes)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want DEBUG", cfg.LogLevel)
	}
}

func TestLoadInvalid(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"port not int", map[string]string{EnvPort: "abc"}},
		{"port zero", map[string]string{EnvPort: "0"}},
		{"port too big", map[string]string{EnvPort: "70000"}},
		{"access ttl bad", map[string]string{EnvAccessTokenTTL: "soon"}},
		{"access ttl negative", map[string]string{EnvAccessTokenTTL: "-1m"}},
		{"refresh ttl bad", map[string]string{EnvRefreshTokenTTL: "0s"}},
		{"part size not int", map[string]string{EnvPartSize: "big"}},
		{"part size too small", map[string]string{EnvPartSize: "1"}},
		{"part size too big", map[string]string{EnvPartSize: "99999999999"}},
		{"quota negative", map[string]string{EnvQuotaBytes: "-5"}},
		{"log level bad", map[string]string{EnvLogLevel: "chatty"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(func(k string) string { return tc.env[k] })
			if err == nil {
				t.Fatal("load() = nil error, want error")
			}
		})
	}
}
