package app

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr           string
	DatabaseURL    string
	WriteAPIKeys   []string
	ReadAPIKeys    []string
	RateLimitRPS   float64
	RateLimitBurst int
	TLSCertFile    string
	TLSKeyFile     string
}

func (c Config) AuthEnabled() bool {
	return len(c.WriteAPIKeys) > 0 || len(c.ReadAPIKeys) > 0
}

func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Addr:         getEnv("ADDR", ":8080"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		WriteAPIKeys: splitList(os.Getenv("API_KEYS")),
		ReadAPIKeys:  splitList(os.Getenv("READ_API_KEYS")),
		TLSCertFile:  os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:   os.Getenv("TLS_KEY_FILE"),
	}

	rps, err := strconv.ParseFloat(getEnv("RATE_LIMIT_RPS", "10"), 64)
	if err != nil || rps <= 0 {
		return Config{}, fmt.Errorf("RATE_LIMIT_RPS must be a positive number")
	}
	cfg.RateLimitRPS = rps

	burst, err := strconv.Atoi(getEnv("RATE_LIMIT_BURST", "20"))
	if err != nil || burst <= 0 {
		return Config{}, fmt.Errorf("RATE_LIMIT_BURST must be a positive integer")
	}
	cfg.RateLimitBurst = burst

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile == "" {
		return Config{}, fmt.Errorf("TLS_KEY_FILE is not set")
	}
	if cfg.TLSKeyFile != "" && cfg.TLSCertFile == "" {
		return Config{}, fmt.Errorf("TLS_CERT_FILE is not set")
	}
	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
