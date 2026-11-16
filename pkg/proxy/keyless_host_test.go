package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Keyless mode must only answer under a loopback Host: a DNS-rebound page
// keeps its own Host header.
func TestRequireAuthOrSession_Keyless_HostCheck(t *testing.T) {
	cases := []struct {
		host string
		want int
	}{
		{"localhost", 200}, {"localhost:8080", 200}, {"LOCALHOST:8080", 200}, {"localhost.:8080", 200},
		{"127.0.0.1", 200}, {"127.0.0.1:8080", 200}, {"127.0.0.2:8080", 200},
		{"[::1]", 200}, {"[::1]:8080", 200},
		{"evil.example", 403}, {"evil.example:8080", 403}, {"localhost.evil.example:8080", 403},
		{"127.0.0.1.evil.example", 403}, {"0.0.0.0:8080", 403}, {"host.docker.internal:8080", 403},
		{"192.168.1.5:8080", 403}, {"", 403},
	}
	for _, c := range cases {
		h := requireAuthOrSession("", NewSessionStore(), true, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/approve/ap_x", nil)
		req.Host = c.host
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != c.want {
			t.Errorf("Host %q: got %d, want %d", c.host, w.Code, c.want)
		}
	}
}

// With an API key set, the Host header is not consulted (the key is the gate).
func TestRequireAuthOrSession_Keyed_IgnoresHost(t *testing.T) {
	h := requireAuthOrSession("k", NewSessionStore(), true, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/approve/ap_x", nil)
	req.Host = "guard.example.com"
	req.Header.Set("Authorization", "Bearer k")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != 200 {
		t.Errorf("keyed + bearer under public Host: got %d, want 200", w.Code)
	}
}

// Keyless + Origin: a browser page on another origin (even another localhost
// port) must not reach the control plane; same-origin and Origin-less callers do.
func TestRequireAuthOrSession_Keyless_OriginCheck(t *testing.T) {
	cases := []struct {
		origin string
		want   int
	}{
		{"", 200}, {"http://localhost:8080", 200},
		{"http://localhost:3000", 403}, {"http://evil.example", 403}, {"null", 403},
	}
	for _, c := range cases {
		h := requireAuthOrSession("", NewSessionStore(), true, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/approve/ap_x", nil)
		req.Host = "localhost:8080"
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != c.want {
			t.Errorf("Origin %q: got %d, want %d", c.origin, w.Code, c.want)
		}
	}
}
