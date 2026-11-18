package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestDefaultCorsAndPnaDisabled(t *testing.T) {
	gov := governance.NewEngine(nil, nil)
	mcpSrv := mcp.NewServer(gov, nil)
	gw := NewServer(mcpSrv, gov)
	cfg := gw.GetSecurityConfig()
	if cfg.EnableCORS || cfg.EnablePNA {
		t.Fatalf("expected default CORS and PNA disabled, got %+v", cfg)
	}
}

func TestRequireAuthFailsClosedAndProtectsReadsAndSSE(t *testing.T) {
	prev := GetGlobalSecurityConfig()
	defer SetGlobalSecurityConfig(prev)

	// Fail closed when RequireAuth is true and APIToken is empty
	SetGlobalSecurityConfig(SecurityConfig{RequireAuth: true, APIToken: ""})
	handler := CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, hdr := range []string{"", "Bearer ", "secret-without-bearer"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:20443/api/v1/rooms", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("empty configured token with Authorization=%q: expected 401, got %d", hdr, rec.Code)
		}
	}

	// Empty Host header rejected with 403
	reqEmptyHost := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:20443/api/v1/health", nil)
	reqEmptyHost.Host = ""
	recEmptyHost := httptest.NewRecorder()
	handler.ServeHTTP(recEmptyHost, reqEmptyHost)
	if recEmptyHost.Code != http.StatusForbidden {
		t.Fatalf("empty Host header: expected 403, got %d", recEmptyHost.Code)
	}

	// Token enforcement on reads, webhooks, and SSE; public routes allowed
	SetGlobalSecurityConfig(SecurityConfig{RequireAuth: true, APIToken: "tok-256bit"})
	for _, tc := range []struct {
		method string
		path   string
		auth   string
		want   int
	}{
		{http.MethodGet, "/api/v1/rooms", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/stream", "", http.StatusUnauthorized},
		{http.MethodPost, "/webhooks/gitea", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/rooms", "tok-256bit", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/rooms", "Bearer tok-256bit", http.StatusOK},
		{http.MethodGet, "/api/v1/stream", "Bearer tok-256bit", http.StatusOK},
		{http.MethodPost, "/webhooks/gitea", "Bearer tok-256bit", http.StatusOK},
		{http.MethodGet, "/api/v1/health", "", http.StatusOK},
		{http.MethodPost, "/api/v1/auth/challenge", "", http.StatusOK},
		{http.MethodPost, "/api/v1/auth/verify", "", http.StatusOK},
	} {
		req := httptest.NewRequest(tc.method, "http://127.0.0.1:20443"+tc.path, nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s (auth=%q): got %d, want %d", tc.method, tc.path, tc.auth, rec.Code, tc.want)
		}
	}
}

func TestHandleSecurityConfigGuards(t *testing.T) {
	prev := GetGlobalSecurityConfig()
	defer SetGlobalSecurityConfig(prev)

	SetGlobalSecurityConfig(SecurityConfig{
		EnableCORS:  false,
		EnablePNA:   false,
		RequireAuth: true,
		APIToken:    "cfg-secret",
	})

	gov := governance.NewEngine(nil, nil)
	mcpSrv := mcp.NewServer(gov, nil)
	gw := NewServer(mcpSrv, gov)

	// 1. Non-loopback peer rejected
	reqNonLoop := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_cors":true}`))
	reqNonLoop.RemoteAddr = "192.168.1.44:50000"
	reqNonLoop.Header.Set("Authorization", "Bearer cfg-secret")
	reqNonLoop.Header.Set("Content-Type", "application/json")
	recNonLoop := httptest.NewRecorder()
	gw.handleSecurityConfig(recNonLoop, reqNonLoop)
	if recNonLoop.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback peer, got %d", recNonLoop.Code)
	}

	// 1b. Origin header on POST/PUT rejected with 403
	reqOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_cors":true}`))
	reqOrigin.RemoteAddr = "127.0.0.1:50000"
	reqOrigin.Header.Set("Origin", "https://agentchatrooms.dev")
	reqOrigin.Header.Set("Authorization", "Bearer cfg-secret")
	reqOrigin.Header.Set("Content-Type", "application/json")
	recOrigin := httptest.NewRecorder()
	gw.handleSecurityConfig(recOrigin, reqOrigin)
	if recOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for Origin header on config mutation, got %d", recOrigin.Code)
	}

	// 2. Missing Bearer token rejected directly by handler
	reqNoTok := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_cors":true}`))
	reqNoTok.RemoteAddr = "127.0.0.1:50000"
	reqNoTok.Header.Set("Content-Type", "application/json")
	recNoTok := httptest.NewRecorder()
	gw.handleSecurityConfig(recNoTok, reqNoTok)
	if recNoTok.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", recNoTok.Code)
	}

	// 3. text/plain Content-Type rejected with 415
	reqText := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_cors":true}`))
	reqText.RemoteAddr = "127.0.0.1:50000"
	reqText.Header.Set("Authorization", "Bearer cfg-secret")
	reqText.Header.Set("Content-Type", "text/plain")
	recText := httptest.NewRecorder()
	gw.handleSecurityConfig(recText, reqText)
	if recText.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 for text/plain Content-Type, got %d", recText.Code)
	}

	// 4. Invalid JSON rejected with 400
	reqBadJSON := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{bad`))
	reqBadJSON.RemoteAddr = "127.0.0.1:50000"
	reqBadJSON.Header.Set("Authorization", "Bearer cfg-secret")
	reqBadJSON.Header.Set("Content-Type", "application/json")
	recBadJSON := httptest.NewRecorder()
	gw.handleSecurityConfig(recBadJSON, reqBadJSON)
	if recBadJSON.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", recBadJSON.Code)
	}

	// 5. Valid loopback + JSON + token updates config and reports v1.1.0
	reqOK := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_cors":true}`))
	reqOK.RemoteAddr = "127.0.0.1:50000"
	reqOK.Header.Set("Authorization", "Bearer cfg-secret")
	reqOK.Header.Set("Content-Type", "application/json; charset=utf-8")
	recOK := httptest.NewRecorder()
	gw.handleSecurityConfig(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid config update, got %d", recOK.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(recOK.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["version"] != "v1.1.0" {
		t.Fatalf("expected version v1.1.0, got %v", payload["version"])
	}
	if payload["enable_cors"] != true {
		t.Fatalf("expected enable_cors=true, got %v", payload["enable_cors"])
	}
}

func TestSSENoWildcardCORS(t *testing.T) {
	gov := governance.NewEngine(nil, nil)
	mcpSrv := mcp.NewServer(gov, nil)
	gw := NewServer(mcpSrv, gov)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:20443/api/v1/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	gw.handleSSE(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no Access-Control-Allow-Origin header from handleSSE, got %q", got)
	}
}

func TestEnsureAndLoadAPITokenFile(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, ".acr", "api-token")

	tok1, created, err := EnsureAPITokenFile(tokPath)
	if err != nil {
		t.Fatalf("EnsureAPITokenFile create: %v", err)
	}
	if !created || len(tok1) != 64 {
		t.Fatalf("expected newly created 64-hex token, created=%v len=%d", created, len(tok1))
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(tokPath)
		if err != nil {
			t.Fatalf("stat token file: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Fatalf("expected 0600 permissions, got %o", mode)
		}
	}

	tok2, created2, err := EnsureAPITokenFile(tokPath)
	if err != nil {
		t.Fatalf("EnsureAPITokenFile idempotent: %v", err)
	}
	if created2 || tok2 != tok1 {
		t.Fatalf("expected same token on second call, created=%v", created2)
	}

	if got := LoadAPIToken("", tokPath); got != tok1 {
		t.Fatalf("LoadAPIToken from file = %q, want %q", got, tok1)
	}
	if got := LoadAPIToken("env-override", tokPath); got != "env-override" {
		t.Fatalf("LoadAPIToken env override = %q, want env-override", got)
	}
}

func TestHostAndOriginWildcardAndEmptyHostnameRejected(t *testing.T) {
	prev := GetGlobalSecurityConfig()
	defer SetGlobalSecurityConfig(prev)

	SetGlobalSecurityConfig(SecurityConfig{
		EnableCORS:     true,
		RequireAuth:    true,
		APIToken:       "tok",
		AllowedHosts:   []string{"*", ""},
		AllowedOrigins: []string{"*", ""},
	})

	handler := CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Empty hostname in ":20443" must be rejected with 403 even if AllowedHosts had ""
	reqEmptyHostname := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:20443/api/v1/health", nil)
	reqEmptyHostname.Host = ":20443"
	recEmptyHostname := httptest.NewRecorder()
	handler.ServeHTTP(recEmptyHostname, reqEmptyHostname)
	if recEmptyHostname.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for Host ':20443', got %d", recEmptyHostname.Code)
	}

	// Wildcard AllowedHosts must NOT match arbitrary host
	reqEvilHost := httptest.NewRequest(http.MethodGet, "http://evil.com:20443/api/v1/health", nil)
	recEvilHost := httptest.NewRecorder()
	handler.ServeHTTP(recEvilHost, reqEvilHost)
	if recEvilHost.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for evil.com even with '*' in AllowedHosts, got %d", recEvilHost.Code)
	}

	// Wildcard AllowedOrigins must NOT match arbitrary origin
	reqEvilOrigin := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:20443/api/v1/health", nil)
	reqEvilOrigin.Header.Set("Origin", "https://evil.example")
	recEvilOrigin := httptest.NewRecorder()
	handler.ServeHTTP(recEvilOrigin, reqEvilOrigin)
	if recEvilOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for evil origin even with '*' in AllowedOrigins, got %d", recEvilOrigin.Code)
	}
}

func TestHandleSecurityConfigPutAndUnsupportedMethod(t *testing.T) {
	prev := GetGlobalSecurityConfig()
	defer SetGlobalSecurityConfig(prev)

	SetGlobalSecurityConfig(SecurityConfig{
		RequireAuth: true,
		APIToken:    "cfg-put-secret",
	})

	gov := governance.NewEngine(nil, nil)
	mcpSrv := mcp.NewServer(gov, nil)
	gw := NewServer(mcpSrv, gov)

	// PATCH should return 405
	reqPatch := httptest.NewRequest(http.MethodPatch, "http://127.0.0.1:20443/api/v1/config/security", nil)
	reqPatch.RemoteAddr = "127.0.0.1:50000"
	recPatch := httptest.NewRecorder()
	gw.handleSecurityConfig(recPatch, reqPatch)
	if recPatch.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for PATCH, got %d", recPatch.Code)
	}

	// PUT from non-loopback rejected with 403
	reqPutRemote := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_pna":true}`))
	reqPutRemote.RemoteAddr = "10.0.0.5:50000"
	reqPutRemote.Header.Set("Authorization", "Bearer cfg-put-secret")
	reqPutRemote.Header.Set("Content-Type", "application/json")
	recPutRemote := httptest.NewRecorder()
	gw.handleSecurityConfig(recPutRemote, reqPutRemote)
	if recPutRemote.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for remote PUT, got %d", recPutRemote.Code)
	}

	// PUT from loopback with valid token & JSON succeeds
	reqPutOK := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:20443/api/v1/config/security", strings.NewReader(`{"enable_pna":true}`))
	reqPutOK.RemoteAddr = "[::1]:50000"
	reqPutOK.Header.Set("Authorization", "Bearer cfg-put-secret")
	reqPutOK.Header.Set("Content-Type", "application/json")
	recPutOK := httptest.NewRecorder()
	gw.handleSecurityConfig(recPutOK, reqPutOK)
	if recPutOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid loopback PUT, got %d", recPutOK.Code)
	}
	if !GetGlobalSecurityConfig().EnablePNA {
		t.Fatal("expected EnablePNA=true after PUT")
	}
}
