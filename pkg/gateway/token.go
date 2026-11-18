package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultAPITokenPath returns ~/.acr/api-token.
func DefaultAPITokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".acr", "api-token"), nil
}

// EnsureAPITokenFile returns the trimmed token from path, or generates a 256-bit
// random hex token and writes it with mode 0600 if the file does not exist or is empty.
func EnsureAPITokenFile(path string) (token string, created bool, err error) {
	if path == "" {
		path, err = DefaultAPITokenPath()
		if err != nil {
			return "", false, err
		}
	}

	if data, readErr := os.ReadFile(path); readErr == nil {
		if existing := strings.TrimSpace(string(data)); existing != "" {
			_ = os.Chmod(path, 0600)
			return existing, false, nil
		}
	} else if !os.IsNotExist(readErr) {
		return "", false, fmt.Errorf("read api token %s: %w", path, readErr)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", false, fmt.Errorf("generate api token: %w", err)
	}
	token = hex.EncodeToString(raw)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", false, fmt.Errorf("create token directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", false, fmt.Errorf("open api token %s: %w", path, err)
	}
	if _, writeErr := f.WriteString(token + "\n"); writeErr != nil {
		_ = f.Close()
		return "", false, fmt.Errorf("write api token %s: %w", path, writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return "", false, fmt.Errorf("close api token %s: %w", path, closeErr)
	}
	_ = os.Chmod(path, 0600)
	return token, true, nil
}

// LoadAPIToken returns envToken if non-empty, otherwise reads and trims path
// (defaulting to ~/.acr/api-token). Returns "" if unavailable.
func LoadAPIToken(envToken, path string) string {
	if trimmed := strings.TrimSpace(envToken); trimmed != "" {
		return trimmed
	}
	if path == "" {
		var err error
		path, err = DefaultAPITokenPath()
		if err != nil {
			return ""
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
