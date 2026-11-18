package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"acr-core/pkg/governance"
	"acr-core/pkg/mcp"
)

func TestCorsMiddlewareSecurityGates(t *testing.T) {
	prev := GetGlobalSecurityConfig()
	defer SetGlobalSecurityConfig(prev)

	SetGlobalSecurityConfig(SecurityConfig{
		EnableCORS: true,
		EnablePNA:  true,
		APIToken:   "test-daemon-secret-123",
	})

	handler := CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// 1. Foreign Host header (DNS rebinding) rejected with 403
	reqHost := httptest.NewRequest(http.MethodGet, "http://evil.com:20443/api/v1/rooms", nil)
	recHost := httptest.NewRecorder()
	handler.ServeHTTP(recHost, reqHost)
	if recHost.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign Host header, got %d", recHost.Code)
	}

	// 2. Foreign Origin rejected with 403 and no CORS/PNA headers
	reqEvilOrigin := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1:20443/api/v1/config/security", nil)
	reqEvilOrigin.Header.Set("Origin", "https://evil.example")
	recEvilOrigin := httptest.NewRecorder()
	handler.ServeHTTP(recEvilOrigin, reqEvilOrigin)
	if recEvilOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign Origin preflight, got %d", recEvilOrigin.Code)
	}
	if recEvilOrigin.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("expected empty Access-Control-Allow-Origin on blocked origin")
	}

	// 3. Allowlisted Origin preflight gets exact Origin + PNA (never wildcard '*')
	reqOkPreflight := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1:20443/api/v1/config/security", nil)
	reqOkPreflight.Header.Set("Origin", "https://agentchatrooms.dev")
	recOkPreflight := httptest.NewRecorder()
	handler.ServeHTTP(recOkPreflight, reqOkPreflight)
	if recOkPreflight.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for allowlisted Origin preflight, got %d", recOkPreflight.Code)
	}
	if got := recOkPreflight.Header().Get("Access-Control-Allow-Origin"); got != "https://agentchatrooms.dev" {
		t.Fatalf("expected exact origin reflection, got %q", got)
	}
	if got := recOkPreflight.Header().Get("Access-Control-Allow-Private-Network"); got != "true" {
		t.Fatalf("expected PNA preflight header 'true', got %q", got)
	}

	// 4. Protected route without Bearer token rejected with 401
	reqNoAuth := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", nil)
	recNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing bearer token, got %d", recNoAuth.Code)
	}

	// 5. Public /health route permitted without Bearer token
	reqHealth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:20443/health", nil)
	recHealth := httptest.NewRecorder()
	handler.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 on /health without token, got %d", recHealth.Code)
	}

	// 6. Protected route with valid Bearer token allowed
	reqValidAuth := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", nil)
	reqValidAuth.Header.Set("Authorization", "Bearer test-daemon-secret-123")
	recValidAuth := httptest.NewRecorder()
	handler.ServeHTTP(recValidAuth, reqValidAuth)
	if recValidAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid bearer token, got %d", recValidAuth.Code)
	}
}

func TestHandleFileUploadMaxBytesCap(t *testing.T) {
	gov := governance.NewEngine(nil, nil)
	mcpSrv := mcp.NewServer(gov, nil)
	gw := NewServer(mcpSrv, gov)

	oversized := bytes.Repeat([]byte("a"), int(maxUploadBytes)+64)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/files/upload?filename=big.bin", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()
	gw.handleFileUpload(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d", rec.Code)
	}
}
