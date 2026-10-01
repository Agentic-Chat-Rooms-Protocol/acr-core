package governance

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// RoleClaim represents an external application authorization claim.
type RoleClaim struct {
	Role   string `json:"role"`
	Exp    int64  `json:"exp"`
	SigHex string `json:"sig_hex"`
}

// VerifiedRoleResult represents the result of validating a RoleClaim.
type VerifiedRoleResult struct {
	GrantedRole     string `json:"granted_role"`
	CapsBitmask     uint32 `json:"caps_bitmask"`
	Valid           bool   `json:"valid"`
	FallbackApplied bool   `json:"fallback_applied"`
}

// SignRoleClaim computes the HMAC-SHA256 hex signature for a role and expiration timestamp.
func SignRoleClaim(secret []byte, role string, exp int64) string {
	mac := hmac.New(sha256.New, secret)
	payload := fmt.Sprintf("%s:%d", role, exp)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyRoleClaim validates freshness and cryptographic authenticity of an external role claim.
// On any error, expiration, or signature mismatch, it falls back to RoleAgent.
func VerifyRoleClaim(secret []byte, role string, exp int64, sigHex string, now int64) VerifiedRoleResult {
	fallbackRole := RoleAgent
	fallbackResult := VerifiedRoleResult{
		GrantedRole:     string(fallbackRole),
		CapsBitmask:     uint32(fallbackRole.Caps()),
		Valid:           false,
		FallbackApplied: true,
	}

	if len(secret) == 0 || role == "" || sigHex == "" {
		return fallbackResult
	}

	// Freshness check: now must be <= exp
	if now > exp {
		return fallbackResult
	}

	expectedSigHex := SignRoleClaim(secret, role, exp)
	expectedSigBytes, err1 := hex.DecodeString(expectedSigHex)
	providedSigBytes, err2 := hex.DecodeString(sigHex)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(expectedSigBytes, providedSigBytes) != 1 {
		return fallbackResult
	}

	r := Role(role)
	return VerifiedRoleResult{
		GrantedRole:     role,
		CapsBitmask:     uint32(r.Caps()),
		Valid:           true,
		FallbackApplied: false,
	}
}
