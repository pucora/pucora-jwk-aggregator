package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

// Config for the JWK aggregator sidecar server.
type Config struct {
	Port    int      `json:"port"`
	Origins []string `json:"origins"`
	Cache   bool     `json:"cache"`
}

// Server merges JWK sets from multiple identity providers.
type Server struct {
	cfg   Config
	cache map[string]cachedJWK
	mu    sync.RWMutex
}

type cachedJWK struct {
	body      []byte
	expiresAt time.Time
}

// NewServer creates an aggregator for the given configuration.
func NewServer(cfg Config) *Server {
	return &Server{cfg: cfg, cache: map[string]cachedJWK{}}
}

// Start launches a localhost-only HTTP server serving the merged JWK set.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		keys, err := s.AggregateKeys(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	})
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.cfg.Port))
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// AggregateKeys fetches and merges keys from all configured origins.
func (s *Server) AggregateKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	var merged []jose.JSONWebKey
	for _, origin := range s.cfg.Origins {
		body, err := s.fetch(ctx, origin)
		if err != nil {
			return nil, err
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(body, &set); err != nil {
			return nil, err
		}
		merged = append(merged, set.Keys...)
	}
	return merged, nil
}

func (s *Server) fetch(ctx context.Context, url string) ([]byte, error) {
	if s.cfg.Cache {
		s.mu.RLock()
		if item, ok := s.cache[url]; ok && time.Now().Before(item.expiresAt) {
			s.mu.RUnlock()
			return item.body, nil
		}
		s.mu.RUnlock()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if s.cfg.Cache {
		ttl := 5 * time.Minute
		if cc := resp.Header.Get("Cache-Control"); cc != "" {
			if d, err := time.ParseDuration(parseMaxAge(cc)); err == nil && d > 0 {
				ttl = d
			}
		}
		s.mu.Lock()
		s.cache[url] = cachedJWK{body: body, expiresAt: time.Now().Add(ttl)}
		s.mu.Unlock()
	}
	return body, nil
}

func parseMaxAge(cc string) string {
	const prefix = "max-age="
	for _, part := range splitCSV(cc) {
		part = trimSpace(part)
		if len(part) > len(prefix) && part[:len(prefix)] == prefix {
			return part[len(prefix):] + "s"
		}
	}
	return ""
}

func splitCSV(v string) []string {
	var out []string
	start := 0
	for i := 0; i < len(v); i++ {
		if v[i] == ',' {
			out = append(out, v[start:i])
			start = i + 1
		}
	}
	out = append(out, v[start:])
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
