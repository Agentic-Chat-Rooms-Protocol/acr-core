package gateway

import (
	"encoding/json"
	"strings"
)

var sensitiveKeys = []string{
	"email",
	"ip",
	"host",
	"token",
	"secret",
	"key",
	"phone",
	"password",
}

func isSensitiveKey(key string) bool {
	lk := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

// StripPII recursively redacts sensitive keys from maps and slices, replacing values with "[redacted]".
// Returns the sanitized data structure and the count of redacted values.
func StripPII(data any) (any, int) {
	redactedCount := 0

	var scrub func(val any) any
	scrub = func(val any) any {
		switch v := val.(type) {
		case map[string]any:
			out := make(map[string]any, len(v))
			for k, item := range v {
				if isSensitiveKey(k) {
					out[k] = "[redacted]"
					redactedCount++
				} else {
					out[k] = scrub(item)
				}
			}
			return out
		case []any:
			out := make([]any, len(v))
			for i, item := range v {
				out[i] = scrub(item)
			}
			return out
		default:
			return v
		}
	}

	sanitized := scrub(data)
	return sanitized, redactedCount
}

// StripPIIJSON parses a raw JSON payload, redacts sensitive keys recursively, and returns the sanitized JSON.
func StripPIIJSON(jsonBytes []byte) ([]byte, int, error) {
	var decoded any
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		return nil, 0, err
	}

	sanitized, count := StripPII(decoded)
	outBytes, err := json.Marshal(sanitized)
	if err != nil {
		return nil, 0, err
	}

	return outBytes, count, nil
}
