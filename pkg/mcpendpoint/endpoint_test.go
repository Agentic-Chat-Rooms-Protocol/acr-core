package mcpendpoint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type endpointVectors struct {
	Remote []struct {
		Input string `json:"input"`
		Valid bool   `json:"valid"`
	} `json:"remote"`
	Local []struct {
		Input      string `json:"input"`
		Valid      bool   `json:"valid"`
		Normalized string `json:"normalized"`
	} `json:"local"`
	Resolve []struct {
		Name        string   `json:"name"`
		Override    string   `json:"override"`
		Scopes      []string `json:"scopes"`
		LocalURL    string   `json:"localURL"`
		ExpectMode  string   `json:"expectMode"`
		ExpectURL   string   `json:"expectURL"`
		ExpectError bool     `json:"expectError"`
	} `json:"resolve"`
}

func loadVectors(t *testing.T) endpointVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "endpoint-vectors.json"))
	if err != nil {
		t.Fatalf("read endpoint-vectors.json: %v", err)
	}
	var v endpointVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal endpoint-vectors.json: %v", err)
	}
	return v
}

func TestValidateRemoteVectors(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Remote {
		err := ValidateRemote(tc.Input)
		if tc.Valid && err != nil {
			t.Errorf("ValidateRemote(%q) unexpected error: %v", tc.Input, err)
		}
		if !tc.Valid && err == nil {
			t.Errorf("ValidateRemote(%q) expected error, got nil", tc.Input)
		}
	}
}

func TestValidateLocalVectors(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Local {
		got, err := ValidateLocal(tc.Input)
		if tc.Valid {
			if err != nil {
				t.Errorf("ValidateLocal(%q) unexpected error: %v", tc.Input, err)
				continue
			}
			if got != tc.Normalized {
				t.Errorf("ValidateLocal(%q) = %q, want %q", tc.Input, got, tc.Normalized)
			}
		} else if err == nil {
			t.Errorf("ValidateLocal(%q) expected error, got %q", tc.Input, got)
		}
	}
}

func TestResolveVectors(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Resolve {
		res, err := Resolve(tc.Override, tc.Scopes, tc.LocalURL)
		if tc.ExpectError {
			if err == nil {
				t.Errorf("%s: expected error, got %+v", tc.Name, res)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.Name, err)
			continue
		}
		if string(res.Mode) != tc.ExpectMode {
			t.Errorf("%s: mode = %q, want %q", tc.Name, res.Mode, tc.ExpectMode)
		}
		if res.URL != tc.ExpectURL {
			t.Errorf("%s: url = %q, want %q", tc.Name, res.URL, tc.ExpectURL)
		}
	}
}

func TestHTTPClientsRejectRedirectsAndPreserveTimeouts(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leak", http.StatusFound)
	}))
	defer redirector.Close()

	restClient := NewHTTPClient()
	if restClient.Timeout != RESTTimeout {
		t.Fatalf("NewHTTPClient().Timeout = %v, want %v", restClient.Timeout, RESTTimeout)
	}
	if _, err := restClient.Get(redirector.URL); err == nil {
		t.Fatal("expected NewHTTPClient to error on 302 redirect")
	}

	streamClient := NewStreamClient()
	if streamClient.Timeout != 0 {
		t.Fatalf("NewStreamClient().Timeout = %v, want 0", streamClient.Timeout)
	}
	tr, ok := streamClient.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout != RESTTimeout {
		t.Fatalf("NewStreamClient() ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, RESTTimeout)
	}
	if _, err := streamClient.Get(redirector.URL); err == nil {
		t.Fatal("expected NewStreamClient to error on 302 redirect")
	}

	if hits := targetHits.Load(); hits != 0 {
		t.Fatalf("redirect target was hit %d times, want 0", hits)
	}
}
