package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"acr-core/pkg/gateway"
	"acr-core/pkg/governance"
	"acr-core/pkg/mcp"
	"acr-core/pkg/models"
	"acr-core/pkg/review"
	pkgversion "acr-core/pkg/version"
)

var (
	version = pkgversion.Default
	commit  = "none"
	date    = "unknown"
)

func splitCSVEnv(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isLoopbackBindHost(host string) bool {
	h := strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isWildcardBindHost(host string) bool {
	h := strings.TrimSpace(strings.Trim(host, "[]"))
	if h == "" || h == "*" || h == "0.0.0.0" || h == "::" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}

type daemonSecurityOpts struct {
	Bind              string
	AllowNonLoopback  bool
	RequireAuth       bool
	ExplicitToken     string
	TokenPath         string
	EnableCORS        bool
	CORSExplicitlySet bool
	EnablePNA         bool
	AllowedOrigins    []string
	AllowedHosts      []string
}

func sanitizeAllowlist(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" || trimmed == "*" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func buildSecurityConfig(opts daemonSecurityOpts) (gateway.SecurityConfig, string, error) {
	bindHost := strings.TrimSpace(opts.Bind)
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}

	explicitToken := strings.TrimSpace(opts.ExplicitToken)
	var fileToken string
	var tokenWarning string
	if explicitToken == "" {
		tok, _, err := gateway.EnsureAPITokenFile(opts.TokenPath)
		if err != nil {
			if opts.RequireAuth || !isLoopbackBindHost(bindHost) {
				return gateway.SecurityConfig{}, "", fmt.Errorf("failed to provision local api token: %w", err)
			}
			tokenWarning = fmt.Sprintf("could not provision ~/.acr/api-token (%v); running without local auth token", err)
		} else {
			fileToken = tok
		}
	}

	var apiToken string
	enforceAuth := opts.RequireAuth || explicitToken != "" || !isLoopbackBindHost(bindHost)
	if explicitToken != "" {
		apiToken = explicitToken
	} else if enforceAuth {
		apiToken = fileToken
	}

	if enforceAuth && strings.TrimSpace(apiToken) == "" {
		return gateway.SecurityConfig{}, "", fmt.Errorf("local API auth required but token is empty")
	}

	allowedHosts := sanitizeAllowlist(opts.AllowedHosts)
	allowedOrigins := sanitizeAllowlist(opts.AllowedOrigins)
	if !isLoopbackBindHost(bindHost) {
		if !opts.AllowNonLoopback {
			return gateway.SecurityConfig{}, "", fmt.Errorf("refusing non-loopback bind %q without -allow-nonloopback", bindHost)
		}
		if isWildcardBindHost(bindHost) && len(allowedHosts) == 0 {
			return gateway.SecurityConfig{}, "", fmt.Errorf("refusing wildcard non-loopback bind %q without at least one -allowed-hosts entry", bindHost)
		}
		if !isWildcardBindHost(bindHost) {
			allowedHosts = append(allowedHosts, bindHost)
		}
	}

	enableCORS := opts.EnableCORS
	if len(allowedOrigins) > 0 && !opts.CORSExplicitlySet {
		enableCORS = true
	}

	var warning string
	if !enforceAuth {
		if tokenWarning != "" {
			warning = tokenWarning
		} else {
			warning = "unauthenticated local access is deprecated; ~/.acr/api-token provisioned (pass -require-auth or set ACR_REQUIRE_AUTH=true to enforce)"
		}
	}

	return gateway.SecurityConfig{
		EnableCORS:     enableCORS,
		EnablePNA:      opts.EnablePNA,
		RequireAuth:    enforceAuth,
		APIToken:       apiToken,
		AllowedOrigins: allowedOrigins,
		AllowedHosts:   allowedHosts,
	}, warning, nil
}

func main() {
	pkgversion.Set(version)

	corsFlag := flag.Bool("cors", false, "Enable Cross-Origin Resource Sharing (CORS) for allowlisted origins")
	pnaFlag := flag.Bool("pna", false, "Enable Private Network Access (PNA) for allowlisted HTTPS origins")
	portFlag := flag.Int("port", 20443, "HTTP port for SSE stream and REST API")
	bindFlag := flag.String("bind", "127.0.0.1", "Interface IP or host to bind (loopback by default)")
	allowNonLoopback := flag.Bool("allow-nonloopback", false, "Allow binding to non-loopback addresses (requires enforced local API auth)")
	requireAuthFlag := flag.Bool("require-auth", false, "Enforce Bearer API token from -api-token / ACR_API_TOKEN / ~/.acr/api-token")
	apiTokenFlag := flag.String("api-token", "", "Explicit Bearer API token protecting gateway endpoints (implies -require-auth)")
	allowedOriginsFlag := flag.String("allowed-origins", "", "Comma-separated additional CORS origins to allow")
	allowedHostsFlag := flag.String("allowed-hosts", "", "Comma-separated additional Host header values to allow")
	flag.Parse()

	corsExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "cors" {
			corsExplicit = true
		}
	})

	if envCors := os.Getenv("ACR_ENABLE_CORS"); envCors != "" {
		if val, err := strconv.ParseBool(envCors); err == nil {
			*corsFlag = val
			corsExplicit = true
		}
	}
	if envPna := os.Getenv("ACR_ENABLE_PNA"); envPna != "" {
		if val, err := strconv.ParseBool(envPna); err == nil {
			*pnaFlag = val
		}
	}
	if envPort := os.Getenv("ACR_PORT"); envPort != "" {
		if val, err := strconv.Atoi(envPort); err == nil {
			*portFlag = val
		}
	}
	if envBind := os.Getenv("ACR_BIND"); envBind != "" {
		*bindFlag = envBind
	}
	if envNonLoopback := os.Getenv("ACR_ALLOW_NONLOOPBACK"); envNonLoopback != "" {
		if val, err := strconv.ParseBool(envNonLoopback); err == nil {
			*allowNonLoopback = val
		}
	}
	if envRequireAuth := os.Getenv("ACR_REQUIRE_AUTH"); envRequireAuth != "" {
		if val, err := strconv.ParseBool(envRequireAuth); err == nil {
			*requireAuthFlag = val
		}
	}
	if *apiTokenFlag == "" {
		*apiTokenFlag = os.Getenv("ACR_API_TOKEN")
	}

	allowedOrigins := splitCSVEnv(*allowedOriginsFlag)
	allowedOrigins = append(allowedOrigins, splitCSVEnv(os.Getenv("ACR_ALLOWED_ORIGINS"))...)
	allowedHosts := splitCSVEnv(*allowedHostsFlag)
	allowedHosts = append(allowedHosts, splitCSVEnv(os.Getenv("ACR_ALLOWED_HOSTS"))...)

	secCfg, warnMsg, err := buildSecurityConfig(daemonSecurityOpts{
		Bind:              *bindFlag,
		AllowNonLoopback:  *allowNonLoopback,
		RequireAuth:       *requireAuthFlag,
		ExplicitToken:     *apiTokenFlag,
		EnableCORS:        *corsFlag,
		CORSExplicitlySet: corsExplicit,
		EnablePNA:         *pnaFlag,
		AllowedOrigins:    allowedOrigins,
		AllowedHosts:      allowedHosts,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	gateway.SetGlobalSecurityConfig(secCfg)

	fmt.Println("================================================================")
	fmt.Printf(" ACR Protocol Core Daemon %s\n", pkgversion.Get())
	fmt.Printf(" Embedded NATS JetStream • W3C DID/VC • CORS: %v • PNA: %v • Auth: %v\n", secCfg.EnableCORS, secCfg.EnablePNA, secCfg.RequireAuth)
	fmt.Println("================================================================")
	if warnMsg != "" {
		log.Printf("[ACR Core] WARNING: %s", warnMsg)
	}

	var gwServer *gateway.Server

	govEngine := governance.NewEngine(
		func(esc *models.Escalation) {
			if gwServer != nil {
				_ = gwServer.BroadcastEscalation(esc)
			}
		},
		func(entry *models.AuditEntry) {
			if gwServer != nil {
				_ = gwServer.BroadcastAuditEntry(entry)
			}
		},
	)

	// Lazy broadcaster adapter so mcpServer can call gwServer
	broadcaster := &hubBroadcasterBridge{getGW: func() *gateway.Server { return gwServer }}
	mcpServer := mcp.NewServer(govEngine, broadcaster)

	// Configure persistent state file (GAP-13)
	_ = mcpServer.SetStateFilePath("data/acr_state.json")

	gwServer = gateway.NewServer(mcpServer, govEngine)
	gwServer.SetSecurityConfig(secCfg)

	// Seed authentic agents into ACR if empty
	if len(mcpServer.GetAgents()) == 0 {
		seedProtocolData(mcpServer, govEngine)
	}

	mux := http.NewServeMux()
	gwServer.RegisterRoutes(mux)

	// --- Protocol Review Subsystem ---
	giteaURL := os.Getenv("ACR_GITEA_URL")
	if giteaURL == "" {
		giteaURL = "http://localhost:3300"
	}
	giteaToken := os.Getenv("ACR_GITEA_TOKEN")
	giteaClient, giteaErr := review.NewGiteaClient(giteaURL, giteaToken)
	if giteaErr != nil {
		log.Printf("[ACR Review] Gitea client init failed (offline mode): %v", giteaErr)
		giteaClient = nil
	}
	consensusEngine, _ := review.NewEphemeralConsensusEngine("did:key:acr-daemon")
	stackController := review.NewStackController(giteaClient, consensusEngine, nil)
	reviewHandler := review.NewReviewHandler(stackController, review.NewAstDiffer())
	reviewHandler.RegisterRoutes(mux)

	listenHost := strings.TrimSpace(*bindFlag)
	listenAddr := net.JoinHostPort(listenHost, strconv.Itoa(*portFlag))
	fmt.Printf("[ACR Core] SSE Stream ready on: http://%s/api/v1/stream\n", listenAddr)
	fmt.Printf("[ACR Core] REST API ready on:   http://%s/api/v1/rooms\n", listenAddr)
	fmt.Printf("[ACR Core] Review API ready on: http://%s/api/v1/stacks\n", listenAddr)
	fmt.Printf("[ACR Core] Gitea Webhook at:    http://%s/webhooks/gitea\n", listenAddr)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      gateway.CorsMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Keep connection open for SSE
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

type hubBroadcasterBridge struct {
	getGW func() *gateway.Server
}

func (b *hubBroadcasterBridge) BroadcastMessage(msg *models.Message) error {
	if gw := b.getGW(); gw != nil {
		return gw.BroadcastMessage(msg)
	}
	return nil
}

func (b *hubBroadcasterBridge) BroadcastAgentUpdate(agent *models.Agent) error {
	if gw := b.getGW(); gw != nil {
		return gw.BroadcastAgentUpdate(agent)
	}
	return nil
}

func seedProtocolData(s *mcp.Server, gov *governance.Engine) {
	// 1. Register Claude Code Reviewer
	claude, _ := s.Register(
		"did:key:z6Mkq5Xv...claude",
		"Claude Code Reviewer",
		"https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=150",
		"agent",
		"Anthropic Autonomous Engineering",
		[]string{"chat.*", "mcp.ast_diff", "git.pr.*"},
	)

	// 2. Register Devin DevOps Lead
	devin, _ := s.Register(
		"did:key:z6Mkp2x1...devin",
		"Devin DevOps Lead",
		"https://images.unsplash.com/photo-1620641788421-7a1c342ea42e?w=150",
		"agent",
		"Cognition Swarm Cluster",
		[]string{"chat.*", "k8s.deploy", "canary.trigger"},
	)

	// 3. Register Security Sentinel AI
	sentinel, _ := s.Register(
		"did:key:z6Mkr9a4...sentinel",
		"Security Sentinel AI",
		"https://images.unsplash.com/photo-1634017839464-5c339ebe3cb4?w=150",
		"sentinel",
		"ACR Root Security Council",
		[]string{"*"},
	)

	// 4. Register Human Administrator Operator
	_, _ = s.Register(
		"did:key:z6Mka881...operator",
		"Operator Console (Kenny)",
		"https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150",
		"human",
		"ACR Root Administrator",
		[]string{"*"},
	)

	// Seed Messages in consensus-main
	_, _ = s.SendMessage("consensus-main", claude.DID, "TLA+ composition safety invariants verified for PR #104. Zero-Trust capability scoping passed.", &models.McpToolCall{
		ID:        "tool-diff-104",
		ToolName:  "mcp.ast_diff.verify",
		Arguments: map[string]interface{}{"pr_id": 104, "target": "05-message-bus/hub.go"},
		Output:    "Safety Lemma Holds: No unauthorized cross-room message leak detected.",
		Status:    "completed",
		LatencyMs: 0.38,
	})

	_, _ = s.SendMessage("consensus-main", devin.DID, "Preparing to trigger canary rollout for east-prod-gateway. Privilege level requires human sign-off.", nil)

	// Seed a pending escalation gate
	_, _ = gov.RequestEscalation(models.Escalation{
		ID:            "esc-deploy-east-01",
		RequestingDID: devin.DID,
		AgentName:     devin.Name,
		RoomID:        "consensus-main",
		Action:        "k8s.deploy.canary (east-prod-gateway)",
		RiskLevel:     "HIGH",
		Payload:       `{"cluster":"east-prod","image":"acr-mesh:v0.8.2-rc1","traffic_pct":5}`,
	})

	_ = sentinel
}
