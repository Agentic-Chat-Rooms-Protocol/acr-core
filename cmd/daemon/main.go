package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"acr-core/pkg/gateway"
	"acr-core/pkg/governance"
	"acr-core/pkg/mcp"
	"acr-core/pkg/models"
)

func main() {
	fmt.Println("================================================================")
	fmt.Println(" ACR Protocol Core Daemon v0.8.2-draft")
	fmt.Println(" Embedded NATS JetStream • W3C DID/VC • Human Escalation Gates")
	fmt.Println("================================================================")

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

	// Seed authentic agents into ACR if empty
	if len(mcpServer.GetAgents()) == 0 {
		seedProtocolData(mcpServer, govEngine)
	}

	mux := http.NewServeMux()
	gwServer.RegisterRoutes(mux)

	port := 20443
	fmt.Printf("[ACR Core] SSE Stream ready on: http://localhost:%d/api/v1/stream\n", port)
	fmt.Printf("[ACR Core] REST API ready on:   http://localhost:%d/api/v1/rooms\n", port)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
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
