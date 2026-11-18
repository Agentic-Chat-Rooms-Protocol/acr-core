package mcpendpoint

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// RemoteURL is compiled in. No flag, env var, file or server response may change it.
	RemoteURL        = "https://mcp.agentchatrooms.dev/mcp"
	DefaultLocalPort = 20443
	// RESTTimeout matches the 10 s client timeout cmd/mcp-server uses.
	RESTTimeout = 10 * time.Second
)

// Mode selects the MCP endpoint tier.
type Mode string

const (
	Local  Mode = "local"
	Remote Mode = "remote"
)

var requiredScopes = []string{"acr:rooms", "acr:cloud:pro"}

// ValidateRemote accepts exactly RemoteURL after parsing, so lookalikes, userinfo,
// alternate ports, queries and fragments are all rejected.
func ValidateRemote(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "#") {
		return errors.New("remote: invalid URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	want, _ := url.Parse(RemoteURL)
	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") {
		return errors.New("remote: scheme, userinfo, query or fragment not allowed")
	}
	if !strings.EqualFold(u.Hostname(), want.Hostname()) || (u.Port() != "" && u.Port() != "443") ||
		u.EscapedPath() != want.Path {
		return errors.New("remote: host or path not allowlisted")
	}
	return nil
}

// ValidateLocal accepts only a loopback literal (or localhost pinned to 127.0.0.1)
// so a hosts-file or DNS answer cannot redirect it.
func ValidateLocal(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "#") {
		return "", errors.New("local: invalid URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") ||
		u.RawPath != "" || strings.HasSuffix(u.Host, ":") {
		return "", errors.New("local: scheme, userinfo, path, query or fragment not allowed")
	}
	host := u.Hostname()
	switch {
	case strings.EqualFold(host, "localhost"):
		host = "127.0.0.1" // pin to the literal; never resolve the name
	case host == "127.0.0.1" || host == "::1":
		// exact literals only: no 127.1, decimal, hex or IPv4-mapped forms
	default:
		return "", errors.New("local: host must be localhost, 127.0.0.1 or ::1")
	}
	port := DefaultLocalPort
	if p := u.Port(); p != "" {
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return "", errors.New("local: port must be 1024-65535")
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1024 || n > 65535 {
			return "", errors.New("local: port must be 1024-65535")
		}
		port = n
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// Resolution describes the selected MCP endpoint and why it was chosen.
type Resolution struct {
	Mode   Mode
	URL    string
	Reason string
}

// Resolve picks a mode. override is "", "local" or "remote" and selects the mode only.
// scopes are the scopes the authorization server granted; they are a routing hint, because
// the gateway enforces entitlement on every call.
func Resolve(override string, scopes []string, localURL string) (Resolution, error) {
	local, err := ValidateLocal(localURL)
	if err != nil {
		return Resolution{}, err
	}
	switch override {
	case "local":
		return Resolution{Mode: Local, URL: local, Reason: "explicit override"}, nil
	case "remote":
		return Resolution{Mode: Remote, URL: RemoteURL, Reason: "explicit override"}, nil
	case "":
	default:
		return Resolution{}, errors.New("override must be local or remote")
	}
	if hasAll(scopes, requiredScopes) {
		return Resolution{Mode: Remote, URL: RemoteURL, Reason: "granted scopes include acr:cloud:pro"}, nil
	}
	return Resolution{Mode: Local, URL: local, Reason: "no paid scope; default"}, nil
}

func hasAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, s := range have {
		set[s] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

var errRedirect = errors.New("mcpendpoint: redirects are not followed")

// A non-nil error is required: http.ErrUseLastResponse would hand the 3xx back as a normal
// response, and callers that only check status >= 400 would treat it as success.
func noRedirect(*http.Request, []*http.Request) error { return errRedirect }

// NewHTTPClient is for request/response calls. It keeps the finite timeout and never follows
// redirects, so a 3xx cannot carry a bearer token to another origin.
func NewHTTPClient() *http.Client {
	return &http.Client{Timeout: RESTTimeout, CheckRedirect: noRedirect}
}

// NewStreamClient is for long-lived SSE. An overall Client.Timeout would cut the stream, so it
// is left at zero and the server must instead send response headers within RESTTimeout.
func NewStreamClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = RESTTimeout
	return &http.Client{Transport: tr, CheckRedirect: noRedirect}
}
