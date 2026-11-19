package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"threat-service/internal/api"
	"threat-service/internal/storage"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(storage.NewMemoryStorage()).Routes())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func TestCreateGetUpdateFlow(t *testing.T) {
	srv := newTestServer(t)

	status, body := do(t, srv, http.MethodPost, "/info",
		`{"md5":"D41D8CD98F00B204E9800998ECF8427E","name":"Trojan.Win32.Generic","severity":"high","description":"test"}`)
	if status != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", status, body)
	}
	var created api.ThreatResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Md5 != testMD5 || created.Severity != api.SeverityHigh || created.Description == nil || *created.Description != "test" {
		t.Fatalf("unexpected create response: %s", body)
	}

	status, body = do(t, srv, http.MethodGet, "/info/"+testMD5, "")
	if status != http.StatusOK {
		t.Fatalf("get: want 200, got %d: %s", status, body)
	}

	status, body = do(t, srv, http.MethodPut, "/info/"+testMD5, `{"name":"Updated","severity":"critical"}`)
	if status != http.StatusOK {
		t.Fatalf("update: want 200, got %d: %s", status, body)
	}
	var updated api.ThreatResponse
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" || updated.Description != nil || !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("unexpected update response: %s", body)
	}
}

func TestErrorResponses(t *testing.T) {
	srv := newTestServer(t)
	valid := `{"md5":"` + testMD5 + `","name":"T","severity":"high"}`
	if status, body := do(t, srv, http.MethodPost, "/info", valid); status != http.StatusCreated {
		t.Fatalf("setup: %d %s", status, body)
	}

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"duplicate create", http.MethodPost, "/info", valid, http.StatusConflict},
		{"broken json", http.MethodPost, "/info", `{"md5":`, http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/info", `{"md5":"` + testMD5 + `","name":"T","severty":"high"}`, http.StatusBadRequest},
		{"invalid md5 in body", http.MethodPost, "/info", `{"md5":"hello","name":"T","severity":"high"}`, http.StatusBadRequest},
		{"empty name", http.MethodPost, "/info", `{"md5":"00000000000000000000000000000001","name":" ","severity":"high"}`, http.StatusBadRequest},
		{"invalid severity", http.MethodPost, "/info", `{"md5":"00000000000000000000000000000001","name":"T","severity":"x"}`, http.StatusBadRequest},
		{"too large body", http.MethodPost, "/info", `{"md5":"` + strings.Repeat("a", MaxBodySize) + `"}`, http.StatusBadRequest},
		{"get invalid md5", http.MethodGet, "/info/hello", "", http.StatusBadRequest},
		{"get missing", http.MethodGet, "/info/00000000000000000000000000000000", "", http.StatusNotFound},
		{"update missing", http.MethodPut, "/info/00000000000000000000000000000000", `{"name":"T","severity":"low"}`, http.StatusNotFound},
		{"update invalid md5", http.MethodPut, "/info/zzz", `{"name":"T","severity":"low"}`, http.StatusBadRequest},
		{"update invalid body", http.MethodPut, "/info/" + testMD5, `{"name":"","severity":"low"}`, http.StatusBadRequest},
		{"wrong method", http.MethodDelete, "/info/" + testMD5, "", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := do(t, srv, tt.method, tt.path, tt.body)
			if status != tt.want {
				t.Fatalf("want %d, got %d: %s", tt.want, status, body)
			}
			if status == http.StatusMethodNotAllowed {
				return
			}
			var errResp api.ErrorResponse
			if err := json.Unmarshal(body, &errResp); err != nil || errResp.Message == "" {
				t.Fatalf("body is not ErrorResponse: %s", body)
			}
		})
	}
}
