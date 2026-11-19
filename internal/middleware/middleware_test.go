package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestAPIKeyAuth(t *testing.T) {
	h := APIKeyAuth([]string{"reader"}, []string{"writer"})(okHandler)

	tests := []struct {
		name   string
		method string
		key    string
		want   int
	}{
		{"no key", http.MethodGet, "", http.StatusUnauthorized},
		{"wrong key", http.MethodGet, "nope", http.StatusUnauthorized},
		{"read key can GET", http.MethodGet, "reader", http.StatusOK},
		{"read key cannot POST", http.MethodPost, "reader", http.StatusForbidden},
		{"read key cannot PUT", http.MethodPut, "reader", http.StatusForbidden},
		{"write key can GET", http.MethodGet, "writer", http.StatusOK},
		{"write key can POST", http.MethodPost, "writer", http.StatusOK},
		{"write key can PUT", http.MethodPut, "writer", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/info", nil)
			if tt.key != "" {
				req.Header.Set(APIKeyHeader, tt.key)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("want %d, got %d", tt.want, rec.Code)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	h := NewRateLimiter(1, 3).Middleware(okHandler)

	send := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := range 3 {
		if code := send("10.0.0.1"); code != http.StatusOK {
			t.Fatalf("request %d within burst: want 200, got %d", i+1, code)
		}
	}
	if code := send("10.0.0.1"); code != http.StatusTooManyRequests {
		t.Fatalf("request over burst: want 429, got %d", code)
	}
	if code := send("10.0.0.2"); code != http.StatusOK {
		t.Fatalf("other client must have its own limit: want 200, got %d", code)
	}
}
