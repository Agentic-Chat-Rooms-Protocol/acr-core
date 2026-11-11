// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Adapted from kubernetes-sigs/agent-sandbox (commit 7ea8b7370a0b895a63255d1d4dcf60c8936bf363)
// sandbox-router/authz/scopedtoken_v2.go, scopedtoken.go, authorizer.go, identity.go

package governance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	AuthorizationHeader = "Authorization"
	BearerSchemePrefix  = "Bearer "

	scopedTokenVersion          = "v1"
	scopedTokenMACContext       = "agent-sandbox/scoped-token/" + scopedTokenVersion + "."
	MinScopedTokenSecretLen     = 32
	scopedTokenV2Version        = "v2"
	scopedTokenV2SigningContext = "agent-sandbox/scoped-token/v2."
	maxScopedTokenKeyIDLen      = 128
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")

	untrustedRoutingHeaders = []string{"X-Sandbox-Pod-Ip", "X-Sandbox-Uid"}
)

// AuthorizationTarget is the canonical request identity an Authorizer evaluates.
type AuthorizationTarget struct {
	Namespace   string
	SandboxName string
	SandboxUID  string
	Port        int
	Method      string
	Path        string
}

// NormalizeAuthorizationTarget returns the stable representation used in
// scoped-token claims and request comparisons.
func NormalizeAuthorizationTarget(target AuthorizationTarget) (AuthorizationTarget, error) {
	target.Method = strings.ToUpper(strings.TrimSpace(target.Method))
	if !validHTTPMethod(target.Method) {
		return AuthorizationTarget{}, errors.New("authorization target: invalid HTTP method")
	}
	if target.Namespace == "" || target.SandboxName == "" {
		return AuthorizationTarget{}, errors.New("authorization target: namespace and sandbox name are required")
	}
	if target.Port < 1 || target.Port > 65535 {
		return AuthorizationTarget{}, errors.New("authorization target: port must be between 1 and 65535")
	}
	if target.Path == "" {
		target.Path = "/"
	}
	if !strings.HasPrefix(target.Path, "/") {
		return AuthorizationTarget{}, errors.New("authorization target: path must be absolute")
	}
	decodedPath, err := url.PathUnescape(target.Path)
	if err != nil {
		return AuthorizationTarget{}, errors.New("authorization target: path has invalid percent-encoding")
	}
	pathURL := &url.URL{Path: decodedPath, RawPath: target.Path}
	target.Path = uppercasePercentEncoding(pathURL.EscapedPath())
	return target, nil
}

func uppercasePercentEncoding(value string) string {
	encoded := []byte(value)
	for i := 0; i+2 < len(encoded); i++ {
		if encoded[i] != '%' {
			continue
		}
		encoded[i+1] = uppercaseHex(encoded[i+1])
		encoded[i+2] = uppercaseHex(encoded[i+2])
		i += 2
	}
	return string(encoded)
}

func uppercaseHex(value byte) byte {
	if value >= 'a' && value <= 'f' {
		return value - ('a' - 'A')
	}
	return value
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for i := 0; i < len(method); i++ {
		c := method[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}

// HTTPStatusFor maps an Authorizer error to the HTTP status code.
func HTTPStatusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

type TokenSource string

const (
	TokenSourceHeader TokenSource = "header"
	TokenSourceQuery  TokenSource = "query"
	TokenSourceCookie TokenSource = "cookie"
)

type TokenLocations struct {
	QueryParam string
	CookieName string
}

func BearerTokenFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	h := r.Header.Get(AuthorizationHeader)
	if len(h) < len(BearerSchemePrefix) {
		return "", false
	}
	if !strings.EqualFold(h[:len(BearerSchemePrefix)], BearerSchemePrefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(BearerSchemePrefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

func TokenFromRequest(r *http.Request, loc TokenLocations) (string, TokenSource, bool) {
	if tok, ok := BearerTokenFromRequest(r); ok {
		return tok, TokenSourceHeader, true
	}
	if r == nil {
		return "", "", false
	}
	if loc.QueryParam != "" {
		if tok := r.URL.Query().Get(loc.QueryParam); tok != "" {
			return tok, TokenSourceQuery, true
		}
	}
	if loc.CookieName != "" {
		if c, err := r.Cookie(loc.CookieName); err == nil && c.Value != "" {
			return c.Value, TokenSourceCookie, true
		}
	}
	return "", "", false
}

type scopedClaims struct {
	Namespace string `json:"ns"`
	Name      string `json:"name"`
	Exp       int64  `json:"exp"`
}

type scopedTokenV2Claims struct {
	Namespace   string `json:"ns"`
	SandboxName string `json:"name"`
	SandboxUID  string `json:"uid"`
	Port        int    `json:"port"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Exp         int64  `json:"exp"`
}

type scopedTokenVerificationKeyFile struct {
	Keys []scopedTokenVerificationKey `json:"keys"`
}

type scopedTokenVerificationKey struct {
	KeyID     string `json:"kid"`
	PublicKey string `json:"publicKey"`
}

func normalizeScopedSecret(secret []byte) ([]byte, error) {
	s := bytes.TrimSpace(secret)
	if len(s) < MinScopedTokenSecretLen {
		return nil, fmt.Errorf("scopedtoken: secret must be at least %d bytes after trimming whitespace, got %d", MinScopedTokenSecretLen, len(s))
	}
	return append([]byte(nil), s...), nil
}

// ParseScopedTokenVerificationKeys parses a JSON public-key set for the router.
func ParseScopedTokenVerificationKeys(data []byte) (map[string]ed25519.PublicKey, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var keyFile scopedTokenVerificationKeyFile
	if err := dec.Decode(&keyFile); err != nil {
		return nil, fmt.Errorf("scopedtoken: decode verification keys: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("scopedtoken: verification key file contains trailing data")
		}
		return nil, fmt.Errorf("scopedtoken: decode verification key trailer: %w", err)
	}
	if len(keyFile.Keys) == 0 {
		return nil, errors.New("scopedtoken: verification key file must contain at least one key")
	}

	keys := make(map[string]ed25519.PublicKey, len(keyFile.Keys))
	for _, entry := range keyFile.Keys {
		if !validScopedTokenKeyID(entry.KeyID) {
			return nil, fmt.Errorf("scopedtoken: invalid key ID %q", entry.KeyID)
		}
		if _, exists := keys[entry.KeyID]; exists {
			return nil, fmt.Errorf("scopedtoken: duplicate key ID %q", entry.KeyID)
		}
		key, err := base64.RawURLEncoding.DecodeString(entry.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("scopedtoken: decode public key %q: %w", entry.KeyID, err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("scopedtoken: public key %q must be %d bytes, got %d", entry.KeyID, ed25519.PublicKeySize, len(key))
		}
		keys[entry.KeyID] = append(ed25519.PublicKey(nil), key...)
	}
	return keys, nil
}

// MintScopedToken produces a v1 HMAC token bound to (namespace, name).
func MintScopedToken(secret []byte, namespace, name string, ttl time.Duration) (string, error) {
	key, err := normalizeScopedSecret(secret)
	if err != nil {
		return "", err
	}
	if namespace == "" || name == "" {
		return "", errors.New("scopedtoken: namespace and name are required")
	}
	if ttl < time.Second {
		return "", fmt.Errorf("scopedtoken: ttl must be at least %s (exp has one-second resolution), got %s", time.Second, ttl)
	}
	claims := scopedClaims{Namespace: namespace, Name: name, Exp: time.Now().Add(ttl).Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("scopedtoken: marshal claims: %w", err)
	}
	encPayload := base64.RawURLEncoding.EncodeToString(payload)
	encSig := base64.RawURLEncoding.EncodeToString(signScopedToken(key, encPayload))
	return scopedTokenVersion + "." + encPayload + "." + encSig, nil
}

func signScopedToken(secret []byte, encPayload string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(scopedTokenMACContext))
	mac.Write([]byte(encPayload))
	return mac.Sum(nil)
}

// MintScopedTokenV2 produces an Ed25519 token bound to one canonical authorization target.
func MintScopedTokenV2(privateKey ed25519.PrivateKey, keyID string, target AuthorizationTarget, ttl time.Duration) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("scopedtoken: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	if !validScopedTokenKeyID(keyID) {
		return "", fmt.Errorf("scopedtoken: invalid key ID %q", keyID)
	}
	if target.SandboxUID == "" {
		return "", errors.New("scopedtoken: Sandbox UID is required")
	}
	normalized, err := NormalizeAuthorizationTarget(target)
	if err != nil {
		return "", fmt.Errorf("scopedtoken: %w", err)
	}
	if ttl < time.Second {
		return "", fmt.Errorf("scopedtoken: ttl must be at least %s (exp has one-second resolution), got %s", time.Second, ttl)
	}
	claims := scopedTokenV2Claims{
		Namespace:   normalized.Namespace,
		SandboxName: normalized.SandboxName,
		SandboxUID:  normalized.SandboxUID,
		Port:        normalized.Port,
		Method:      normalized.Method,
		Path:        normalized.Path,
		Exp:         time.Now().Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("scopedtoken: marshal v2 claims: %w", err)
	}
	encPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(privateKey, scopedTokenV2SigningInput(keyID, encPayload))
	return strings.Join([]string{
		scopedTokenV2Version,
		keyID,
		encPayload,
		base64.RawURLEncoding.EncodeToString(signature),
	}, "."), nil
}

func scopedTokenV2SigningInput(keyID, encPayload string) []byte {
	return []byte(scopedTokenV2SigningContext + keyID + "." + encPayload)
}

func validScopedTokenKeyID(keyID string) bool {
	if keyID == "" || len(keyID) > maxScopedTokenKeyIDLen {
		return false
	}
	for i := 0; i < len(keyID); i++ {
		c := keyID[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

type ScopedTokenOptions struct {
	Secret           []byte
	VerificationKeys map[string]ed25519.PublicKey
	V1AcceptUntil    time.Time
	Clock            func() time.Time
	TokenLocations   TokenLocations
}

type ScopedTokenAuthorizer struct {
	secret           []byte
	verificationKeys map[string]ed25519.PublicKey
	v1AcceptUntil    time.Time
	clock            func() time.Time
	locs             TokenLocations
}

func NewScopedTokenAuthorizer(o ScopedTokenOptions) (*ScopedTokenAuthorizer, error) {
	var secret []byte
	if len(bytes.TrimSpace(o.Secret)) > 0 {
		key, err := normalizeScopedSecret(o.Secret)
		if err != nil {
			return nil, err
		}
		secret = key
	}
	verificationKeys := make(map[string]ed25519.PublicKey, len(o.VerificationKeys))
	for keyID, key := range o.VerificationKeys {
		if !validScopedTokenKeyID(keyID) {
			return nil, fmt.Errorf("scopedtoken: invalid key ID %q", keyID)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("scopedtoken: public key %q must be %d bytes, got %d", keyID, ed25519.PublicKeySize, len(key))
		}
		verificationKeys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	if len(secret) == 0 && len(verificationKeys) == 0 {
		return nil, errors.New("scopedtoken: a v1 secret or v2 verification key is required")
	}
	if len(verificationKeys) > 0 && len(secret) > 0 && o.V1AcceptUntil.IsZero() {
		return nil, errors.New("scopedtoken: V1AcceptUntil is required when v1 and v2 verification are both enabled")
	}
	if !o.V1AcceptUntil.IsZero() && len(secret) == 0 {
		return nil, errors.New("scopedtoken: V1AcceptUntil requires a v1 secret")
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	return &ScopedTokenAuthorizer{
		secret:           secret,
		verificationKeys: verificationKeys,
		v1AcceptUntil:    o.V1AcceptUntil,
		clock:            clock,
		locs:             o.TokenLocations,
	}, nil
}

func (a *ScopedTokenAuthorizer) Authorize(_ context.Context, r *http.Request, target AuthorizationTarget) error {
	token, _, ok := TokenFromRequest(r, a.locs)
	if !ok {
		return ErrUnauthenticated
	}
	version, _, _ := strings.Cut(token, ".")
	switch version {
	case scopedTokenVersion:
		claims, err := a.verifyV1(token)
		if err != nil {
			return ErrUnauthenticated
		}
		for _, header := range untrustedRoutingHeaders {
			if r.Header.Get(header) != "" {
				return ErrForbidden
			}
		}
		if claims.Namespace != target.Namespace || claims.Name != target.SandboxName {
			return ErrForbidden
		}
		return nil
	case scopedTokenV2Version:
		claims, err := a.verifyV2(token)
		if err != nil {
			return ErrUnauthenticated
		}
		if r.Header.Get("X-Sandbox-Pod-Ip") != "" {
			return ErrForbidden
		}
		normalized, err := NormalizeAuthorizationTarget(target)
		if err != nil {
			return ErrForbidden
		}
		if normalized.SandboxUID == "" || r == nil || r.Method != normalized.Method {
			return ErrForbidden
		}
		if claims.Namespace != normalized.Namespace ||
			claims.SandboxName != normalized.SandboxName ||
			claims.SandboxUID != normalized.SandboxUID ||
			claims.Port != normalized.Port ||
			claims.Method != normalized.Method ||
			claims.Path != normalized.Path {
			return ErrForbidden
		}
		return nil
	default:
		return ErrUnauthenticated
	}
}

func (a *ScopedTokenAuthorizer) verifyV1(token string) (*scopedClaims, error) {
	if len(a.secret) == 0 {
		return nil, errors.New("scopedtoken: v1 verification is disabled")
	}
	if !a.v1AcceptUntil.IsZero() && !a.clock().Before(a.v1AcceptUntil) {
		return nil, errors.New("scopedtoken: v1 acceptance window expired")
	}
	version, rest, ok := strings.Cut(token, ".")
	if !ok || version != scopedTokenVersion {
		return nil, errors.New("scopedtoken: malformed token")
	}
	encPayload, encSig, ok := strings.Cut(rest, ".")
	if !ok {
		return nil, errors.New("scopedtoken: malformed token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(encSig)
	if err != nil {
		return nil, fmt.Errorf("scopedtoken: decode signature: %w", err)
	}
	if !hmac.Equal(sig, signScopedToken(a.secret, encPayload)) {
		return nil, errors.New("scopedtoken: signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encPayload)
	if err != nil {
		return nil, fmt.Errorf("scopedtoken: decode payload: %w", err)
	}
	var claims scopedClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("scopedtoken: unmarshal claims: %w", err)
	}
	if a.clock().Unix() >= claims.Exp {
		return nil, errors.New("scopedtoken: token expired")
	}
	return &claims, nil
}

func (a *ScopedTokenAuthorizer) verifyV2(token string) (*scopedTokenV2Claims, error) {
	if len(a.verificationKeys) == 0 {
		return nil, errors.New("scopedtoken: v2 verification is disabled")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != scopedTokenV2Version {
		return nil, errors.New("scopedtoken: malformed v2 token")
	}
	key, ok := a.verificationKeys[parts[1]]
	if !ok {
		return nil, errors.New("scopedtoken: unknown key ID")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("scopedtoken: decode v2 signature: %w", err)
	}
	if !ed25519.Verify(key, scopedTokenV2SigningInput(parts[1], parts[2]), signature) {
		return nil, errors.New("scopedtoken: v2 signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("scopedtoken: decode v2 payload: %w", err)
	}
	var claims scopedTokenV2Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("scopedtoken: unmarshal v2 claims: %w", err)
	}
	if claims.SandboxUID == "" {
		return nil, errors.New("scopedtoken: v2 Sandbox UID is required")
	}
	if a.clock().Unix() >= claims.Exp {
		return nil, errors.New("scopedtoken: token expired")
	}
	return &claims, nil
}
