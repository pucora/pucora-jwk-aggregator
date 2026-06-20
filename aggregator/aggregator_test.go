package aggregator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAggregateKeysMergesOrigins(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"idp1","use":"sig","n":"abc","e":"AQAB"}]}`))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"idp2","use":"sig","n":"abc","e":"AQAB"}]}`))
	}))
	defer srv2.Close()

	s := NewServer(Config{Origins: []string{srv1.URL, srv2.URL}})
	keys, err := s.AggregateKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 merged keys, got %d", len(keys))
	}
	if keys[0].KeyID != "idp1" || keys[1].KeyID != "idp2" {
		t.Fatalf("unexpected key IDs: %+v", keys)
	}
}

func TestFetchHonorsCacheControl(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Cache-Control", "max-age=3600")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"cached","n":"abc","e":"AQAB"}]}`))
	}))
	defer srv.Close()

	s := NewServer(Config{Origins: []string{srv.URL}, Cache: true})
	if _, err := s.AggregateKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AggregateKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected cached second fetch, got %d HTTP calls", calls)
	}
}
