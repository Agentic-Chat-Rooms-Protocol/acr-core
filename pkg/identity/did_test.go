package identity

import "testing"

func TestValidateDID(t *testing.T) {
	tests := []struct {
		did   string
		valid bool
	}{
		{"did:key:z6Mkq5Xv", true},
		{"did:web:acr.protocol", true},
		{"invalid:did", false},
		{"did:", false},
		{"did:foo", false},
	}

	for _, tt := range tests {
		if got := ValidateDID(tt.did); got != tt.valid {
			t.Errorf("ValidateDID(%q) = %v; want %v", tt.did, got, tt.valid)
		}
	}
}

func TestCheckCapabilityScope(t *testing.T) {
	caps := []string{"chat.*", "mcp.ast_diff"}

	if !CheckCapabilityScope(caps, "chat.message.send") {
		t.Errorf("expected chat.message.send to be permitted by chat.*")
	}
	if !CheckCapabilityScope(caps, "mcp.ast_diff") {
		t.Errorf("expected mcp.ast_diff to be permitted")
	}
	if CheckCapabilityScope(caps, "k8s.deploy") {
		t.Errorf("expected k8s.deploy to be denied")
	}
}
