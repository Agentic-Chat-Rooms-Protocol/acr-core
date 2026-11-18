package version

import (
	"strings"
	"sync"
)

// Default is the canonical fallback version when not overridden by build ldflags.
const Default = "v1.1.0"

var (
	mu      sync.RWMutex
	current = Default
)

// Normalize ensures a consistent v-prefixed semantic version string.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" {
		return Default
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// Set updates the active runtime version (typically from -ldflags "-X main.version=...").
func Set(v string) {
	mu.Lock()
	defer mu.Unlock()
	current = Normalize(v)
}

// Get returns the active runtime version.
func Get() string {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
