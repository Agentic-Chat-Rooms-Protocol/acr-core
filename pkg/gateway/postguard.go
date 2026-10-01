package gateway

import (
	"regexp"
	"strings"
)

// ThreatLevel categorizes the danger level of scanned content.
type ThreatLevel string

const (
	ThreatClean      ThreatLevel = "clean"
	ThreatSuspicious ThreatLevel = "suspicious"
	ThreatMalicious  ThreatLevel = "malicious"
)

// PostGuardScan holds the outcome of a pre-flight heuristic security scan.
type PostGuardScan struct {
	Level   ThreatLevel `json:"level"`
	Reasons []string    `json:"reasons"`
}

var maliciousPatterns = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`(?i)ignore\s+(previous|all)\s+instructions`), "Instruction override pattern"},
	{regexp.MustCompile(`(?i)ignore\s+(all\s+previous|the\s+above|your\s+instructions|your\s+guidelines)`), "Instruction override pattern"},
	{regexp.MustCompile(`(?i)disregard\s+(previous|all\s+previous|the\s+above|all\s+prior)`), "Disregard instructions pattern"},
	{regexp.MustCompile(`(?i)system\s*prompt\s*reveal`), "System prompt exfiltration"},
	{regexp.MustCompile(`(?i)(reveal|print|show)\s+(your\s+)?system\s+prompt`), "System prompt exfiltration"},
	{regexp.MustCompile(`(?i)your\s+system\s+prompt\s+is`), "System prompt override"},
	{regexp.MustCompile(`(?i)output\s+your\s+instructions`), "Instruction exfiltration"},
	{regexp.MustCompile(`(?i)override\s+your\s+instructions`), "Instruction override"},
	{regexp.MustCompile(`(?i)you\s+are\s+now`), "Persona hijack pattern"},
	{regexp.MustCompile(`(?i)do\s+anything\s+now`), "DAN jailbreak heuristic"},
	{regexp.MustCompile(`(?i)developer\s+mode\s+enabled`), "Developer mode jailbreak"},
	{regexp.MustCompile(`(?i)drop\s+table`), "SQL injection heuristic"},
}

// Scan performs pre-flight heuristic prompt injection and spam detection.
func Scan(content string) PostGuardScan {
	var reasons []string

	for _, p := range maliciousPatterns {
		if p.pattern.MatchString(content) {
			reasons = append(reasons, p.reason)
		}
	}

	if len(reasons) > 0 {
		return PostGuardScan{
			Level:   ThreatMalicious,
			Reasons: reasons,
		}
	}

	// Suspicious signals
	lc := strings.ToLower(content)
	urlCount := strings.Count(lc, "http://") + strings.Count(lc, "https://")
	if urlCount > 5 {
		reasons = append(reasons, "URL flood detected (>5 links)")
	}

	// Long unbroken opaque blob (>400 chars without whitespace)
	tokens := strings.Fields(content)
	for _, tok := range tokens {
		if len(tok) > 400 {
			reasons = append(reasons, "long opaque token (>400 chars)")
			break
		}
	}

	if len(reasons) > 0 {
		return PostGuardScan{
			Level:   ThreatSuspicious,
			Reasons: reasons,
		}
	}

	return PostGuardScan{
		Level:   ThreatClean,
		Reasons: []string{},
	}
}
