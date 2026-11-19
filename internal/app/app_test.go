package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"threat-service/internal/storage"
)

func TestHTTPHandlerIntegration(t *testing.T) {
	cfg := Config{
		WriteAPIKeys:   []string{"write-key"},
		ReadAPIKeys:    []string{"read-key"},
		RateLimitRPS:   1,
		RateLimitBurst: 5,
	}
	srv := httptest.NewServer(NewHTTPHandler(cfg, storage.NewMemoryStorage()))
	t.Cleanup(srv.Close)

	send := func(method, path, key, body string) int {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	body := `{"md5":"` + md5 + `","name":"T","severity":"high"}`

	steps := []struct {
		name   string
		method string
		path   string
		key    string
		body   string
		want   int
	}{
		{"no key", http.MethodGet, "/info/" + md5, "", "", http.StatusUnauthorized},
		{"read key cannot create", http.MethodPost, "/info", "read-key", body, http.StatusForbidden},
		{"write key creates", http.MethodPost, "/info", "write-key", body, http.StatusCreated},
		{"read key reads", http.MethodGet, "/info/" + md5, "read-key", "", http.StatusOK},
		{"burst exhausted", http.MethodGet, "/info/" + md5, "read-key", "", http.StatusOK},
		{"rate limited", http.MethodGet, "/info/" + md5, "read-key", "", http.StatusTooManyRequests},
	}
	for _, s := range steps {
		if got := send(s.method, s.path, s.key, s.body); got != s.want {
			t.Fatalf("%s: want %d, got %d", s.name, s.want, got)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("API_KEYS", " a, b ,,")
	t.Setenv("RATE_LIMIT_RPS", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WriteAPIKeys) != 2 || cfg.WriteAPIKeys[0] != "a" || cfg.WriteAPIKeys[1] != "b" {
		t.Errorf("unexpected keys: %q", cfg.WriteAPIKeys)
	}
	if cfg.Addr != ":8080" || cfg.RateLimitRPS != 10 || cfg.RateLimitBurst != 20 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}

	t.Setenv("TLS_CERT_FILE", "cert.pem")
	if _, err := LoadConfig(); err == nil {
		t.Error("expected error when only TLS_CERT_FILE is set")
	}
}
