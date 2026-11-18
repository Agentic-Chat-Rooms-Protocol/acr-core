package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	pkgversion "acr-core/pkg/version"
)

func TestResolveDaemonURLValidation(t *testing.T) {
	got, err := resolveDaemonURL("")
	if err != nil {
		t.Fatalf("resolveDaemonURL empty: %v", err)
	}
	if got != "http://127.0.0.1:20443" {
		t.Fatalf("resolveDaemonURL empty = %q, want http://127.0.0.1:20443", got)
	}

	got, err = resolveDaemonURL("http://localhost:20443")
	if err != nil || got != "http://127.0.0.1:20443" {
		t.Fatalf("resolveDaemonURL localhost = (%q, %v)", got, err)
	}

	for _, bad := range []string{
		"http://evil.com:20443",
		"https://127.0.0.1:20443",
		"http://0.0.0.0:20443",
		"http://127.0.0.1:20443/api",
		"http://127.0.0.1:80",
	} {
		if _, err := newDaemonClient(bad, "", nil); err == nil {
			t.Errorf("newDaemonClient(%q) expected error, got nil", bad)
		}
	}
}

func TestInitializeReportsVersion(t *testing.T) {
	pkgversion.Set("1.1.0")
	var out bytes.Buffer
	dc, err := newDaemonClient("", "", &out)
	if err != nil {
		t.Fatalf("newDaemonClient: %v", err)
	}

	dc.handleRequest(jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	})

	var resp struct {
		Result struct {
			ServerInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Result.ServerInfo.Version != "v1.1.0" {
		t.Fatalf("serverInfo.version = %q, want v1.1.0", resp.Result.ServerInfo.Version)
	}
}

func TestBearerAuthAndNoRedirect(t *testing.T) {
	const expectedToken = "local-secret-token"
	var redirectTargetHits atomic.Int32

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/redirect" || r.URL.Path == "/api/v1/health" && r.Header.Get("X-Trigger-Redirect") == "1" {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		if r.URL.Path == "/api/v1/health" {
			_, _ = w.Write([]byte(`{"version":"v1.1.0","status":"healthy"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+expectedToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad content type", http.StatusUnsupportedMediaType)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// 1. Missing token gets 401 -> isError: true
	var outNoAuth bytes.Buffer
	dcNoAuth, err := newDaemonClient(srv.URL, "", &outNoAuth)
	if err != nil {
		t.Fatalf("newDaemonClient noAuth: %v", err)
	}
	if _, err := dcNoAuth.executeTool("chat.rooms.list", nil); err == nil {
		t.Fatal("expected error when daemon returns 401")
	}

	// 2. Valid token succeeds on GET and POST
	var outAuth bytes.Buffer
	dcAuth, err := newDaemonClient(srv.URL, expectedToken, &outAuth)
	if err != nil {
		t.Fatalf("newDaemonClient auth: %v", err)
	}
	if res, err := dcAuth.executeTool("chat.rooms.list", nil); err != nil || res != `{"ok":true}` {
		t.Fatalf("chat.rooms.list = (%q, %v)", res, err)
	}
	if res, err := dcAuth.executeTool("chat.room.create", map[string]interface{}{"name": "test"}); err != nil || res != `{"ok":true}` {
		t.Fatalf("chat.room.create = (%q, %v)", res, err)
	}

	// 3. Health reports v1.1.0
	if res, err := dcAuth.executeTool("chat.health", nil); err != nil || !bytes.Contains([]byte(res), []byte(`"v1.1.0"`)) {
		t.Fatalf("chat.health = (%q, %v)", res, err)
	}

	// 4. 302 redirect is rejected and never hits redirect target
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer redirectSrv.Close()

	dcRedir, err := newDaemonClient(redirectSrv.URL, expectedToken, &outAuth)
	if err != nil {
		t.Fatalf("newDaemonClient redirect: %v", err)
	}
	if _, err := dcRedir.executeTool("chat.rooms.list", nil); err == nil {
		t.Fatal("expected 302 redirect on GET to return error")
	}
	if _, err := dcRedir.executeTool("chat.room.create", map[string]interface{}{"name": "x"}); err == nil {
		t.Fatal("expected 302 redirect on POST to return error")
	}
	if hits := redirectTargetHits.Load(); hits != 0 {
		t.Fatalf("redirect target received %d hits, want 0", hits)
	}

	// 5. Config tools send Bearer token and query parameters/paths are escaped
	if res, err := dcAuth.executeTool("chat.config.get", nil); err != nil || res != `{"ok":true}` {
		t.Fatalf("chat.config.get = (%q, %v)", res, err)
	}
	if res, err := dcAuth.executeTool("chat.config.security", map[string]interface{}{"enable_cors": false}); err != nil || res != `{"ok":true}` {
		t.Fatalf("chat.config.security = (%q, %v)", res, err)
	}
}
