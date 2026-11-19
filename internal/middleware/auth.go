package middleware

import (
	"crypto/subtle"
	"net/http"

	"threat-service/internal/respond"
)

const APIKeyHeader = "X-API-Key"

type role int

const (
	roleNone role = iota
	roleRead
	roleWrite
)

func APIKeyAuth(readKeys, writeKeys []string) func(http.Handler) http.Handler {
	keys := make(map[string]role)
	for _, k := range readKeys {
		keys[k] = roleRead
	}
	for _, k := range writeKeys {
		keys[k] = roleWrite
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(APIKeyHeader)
			if key == "" {
				respond.Error(w, http.StatusUnauthorized, "Unauthorized", "missing "+APIKeyHeader+" header")
				return
			}

			got := lookupRole(keys, key)
			if got == roleNone {
				respond.Error(w, http.StatusUnauthorized, "Unauthorized", "invalid API key")
				return
			}
			if got < requiredRole(r.Method) {
				respond.Error(w, http.StatusForbidden, "Forbidden", "this API key is read-only")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func lookupRole(keys map[string]role, key string) role {
	found := roleNone
	for k, r := range keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			found = r
		}
	}
	return found
}

func requiredRole(method string) role {
	if method == http.MethodGet || method == http.MethodHead {
		return roleRead
	}
	return roleWrite
}
