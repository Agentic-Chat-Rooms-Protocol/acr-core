package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"acr-core/pkg/gateway"
	"acr-core/pkg/governance"
	"acr-core/pkg/mcp"
	pkgversion "acr-core/pkg/version"
)

func TestBuildSecurityConfigDefaultsPhase0a(t *testing.T) {
	tokPath := filepath.Join(t.TempDir(), ".acr", "api-token")
	cfg, warn, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:      "127.0.0.1",
		TokenPath: tokPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnableCORS || cfg.EnablePNA {
		t.Fatalf("expected CORS and PNA off by default, got %+v", cfg)
	}
	if cfg.RequireAuth || cfg.APIToken != "" {
		t.Fatalf("expected Phase 0a/0b opt-in auth off by default on loopback, got %+v", cfg)
	}
	if warn == "" {
		t.Fatal("expected deprecation warning when auth enforcement is off")
	}
	data, err := os.ReadFile(tokPath)
	if err != nil || len(strings.TrimSpace(string(data))) != 64 {
		t.Fatalf("expected provisioned 64-hex api-token file, err=%v data=%q", err, string(data))
	}
}

func TestBuildSecurityConfigAuthAndNonLoopback(t *testing.T) {
	tokPath := filepath.Join(t.TempDir(), ".acr", "api-token")

	// Explicit -require-auth provisions and enforces token
	cfg, warn, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:        "127.0.0.1",
		RequireAuth: true,
		TokenPath:   tokPath,
	})
	if err != nil {
		t.Fatalf("unexpected error with RequireAuth: %v", err)
	}
	if !cfg.RequireAuth || len(cfg.APIToken) != 64 || warn != "" {
		t.Fatalf("expected enforced 64-hex token and no warning, got cfg=%+v warn=%q", cfg, warn)
	}

	// Non-loopback without -allow-nonloopback fails
	if _, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:      "192.168.1.10",
		TokenPath: tokPath,
	}); err == nil {
		t.Fatal("expected error for non-loopback bind without -allow-nonloopback")
	}

	// Wildcard non-loopback without -allowed-hosts fails
	if _, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:             "0.0.0.0",
		AllowNonLoopback: true,
		TokenPath:        tokPath,
	}); err == nil {
		t.Fatal("expected error for wildcard bind without -allowed-hosts")
	}

	// Concrete LAN non-loopback with -allow-nonloopback succeeds and enforces auth
	lanCfg, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:             "192.168.1.10",
		AllowNonLoopback: true,
		TokenPath:        tokPath,
	})
	if err != nil {
		t.Fatalf("expected LAN bind to succeed with -allow-nonloopback: %v", err)
	}
	if !lanCfg.RequireAuth || lanCfg.APIToken == "" {
		t.Fatalf("expected auth enforced on non-loopback bind")
	}

	// Allowlist-gated CORS enables CORS when -cors not explicitly set
	corsCfg, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:           "127.0.0.1",
		AllowedOrigins: []string{"https://app.agentchatrooms.dev"},
		TokenPath:      tokPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !corsCfg.EnableCORS {
		t.Fatal("expected EnableCORS=true when AllowedOrigins provided and -cors not explicitly set")
	}

	// Wildcard '*' in -allowed-hosts must not satisfy 0.0.0.0 bind guard
	if _, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:             "0.0.0.0",
		AllowNonLoopback: true,
		AllowedHosts:     []string{"*", " "},
		TokenPath:        tokPath,
	}); err == nil {
		t.Fatal("expected error when wildcard bind only has '*' in AllowedHosts")
	}

	// Wildcard '*' in AllowedOrigins is stripped and does not auto-enable CORS
	wildCorsCfg, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:           "127.0.0.1",
		AllowedOrigins: []string{"*", ""},
		TokenPath:      tokPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wildCorsCfg.EnableCORS || len(wildCorsCfg.AllowedOrigins) != 0 {
		t.Fatalf("expected wildcard origins stripped and CORS disabled, got %+v", wildCorsCfg)
	}
}

func TestDaemonHealthVersionAndAuthIntegration(t *testing.T) {
	prev := gateway.GetGlobalSecurityConfig()
	defer gateway.SetGlobalSecurityConfig(prev)

	pkgversion.Set("1.1.0")
	if got := pkgversion.Get(); got != "v1.1.0" {
		t.Fatalf("version.Get() = %q, want v1.1.0", got)
	}

	tokPath := filepath.Join(t.TempDir(), ".acr", "api-token")
	cfg, _, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:        "127.0.0.1",
		RequireAuth: true,
		TokenPath:   tokPath,
	})
	if err != nil {
		t.Fatalf("buildSecurityConfig: %v", err)
	}
	gateway.SetGlobalSecurityConfig(cfg)

	gov := governance.NewEngine(nil, nil)
	mcpSrv := mcp.NewServer(gov, nil)
	gw := gateway.NewServer(mcpSrv, gov)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	ts := httptest.NewServer(gateway.CorsMiddleware(mux))
	defer ts.Close()

	// Health is public and reports v1.1.0
	res, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET health: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET health status = %d, want 200", res.StatusCode)
	}
	var health map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["version"] != "v1.1.0" {
		t.Fatalf("health.version = %v, want v1.1.0", health["version"])
	}

	// Protected route rejects missing token and accepts Bearer token
	unauthRes, err := http.Get(ts.URL + "/api/v1/rooms")
	if err != nil {
		t.Fatalf("GET rooms unauth: %v", err)
	}
	unauthRes.Body.Close()
	if unauthRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET rooms without token status = %d, want 401", unauthRes.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/rooms", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	authRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET rooms auth: %v", err)
	}
	authRes.Body.Close()
	if authRes.StatusCode != http.StatusOK {
		t.Fatalf("GET rooms with token status = %d, want 200", authRes.StatusCode)
	}
}
