package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"threat-service/internal/respond"
)

const clientTTL = 3 * time.Minute

type RateLimiter struct {
	rps   rate.Limit
	burst int

	mu          sync.Mutex
	clients     map[string]*client
	lastCleanup time.Time
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		rps:         rate.Limit(rps),
		burst:       burst,
		clients:     make(map[string]*client),
		lastCleanup: time.Now(),
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			respond.Error(w, http.StatusTooManyRequests, "Too many requests", "rate limit exceeded, retry later")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastCleanup) > clientTTL {
		for k, c := range rl.clients {
			if now.Sub(c.lastSeen) > clientTTL {
				delete(rl.clients, k)
			}
		}
		rl.lastCleanup = now
	}

	c, ok := rl.clients[ip]
	if !ok {
		c = &client{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.clients[ip] = c
	}
	c.lastSeen = now
	return c.limiter.Allow()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
