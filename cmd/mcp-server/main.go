package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	defaultDaemonURL = "http://localhost:20443"
	protocolVersion  = "2024-11-05"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDefinition struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

func main() {
	daemonURL := os.Getenv("ACR_DAEMON_URL")
	if daemonURL == "" {
		daemonURL = defaultDaemonURL
	}

	client := &http.Client{Timeout: 10 * time.Second}
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendError(nil, -32700, "Parse error")
			continue
		}

		handleRequest(client, daemonURL, req)
	}
}

func handleRequest(client *http.Client, daemonURL string, req jsonRPCRequest) {
	switch req.Method {
	case "initialize":
		sendResult(req.ID, map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{"listChanged": false},
			},
			"serverInfo": map[string]string{
				"name":    "acr-mcp-server",
				"version": "v0.8.2-draft",
			},
		})

	case "notifications/initialized":
		// No response required for notifications

	case "tools/list":
		tools := getToolDefinitions()
		sendResult(req.ID, map[string]interface{}{"tools": tools})

	case "tools/call":
		var callParams struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			sendError(req.ID, -32602, "Invalid params")
			return
		}

		resultText, err := executeTool(client, daemonURL, callParams.Name, callParams.Arguments)
		if err != nil {
			sendResult(req.ID, map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("Error: %v", err)},
				},
				"isError": true,
			})
			return
		}

		sendResult(req.ID, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": resultText},
			},
			"isError": false,
		})

	default:
		sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func executeTool(client *http.Client, daemonURL, toolName string, args map[string]interface{}) (string, error) {
	switch toolName {
	case "chat.health":
		res, err := client.Get(daemonURL + "/api/v1/health")
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return string(body), nil

	case "chat.rooms.list":
		res, err := client.Get(daemonURL + "/api/v1/rooms")
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return string(body), nil

	case "chat.room.create":
		return postJSON(client, daemonURL+"/api/v1/rooms", args)

	case "chat.room.join":
		roomID, _ := args["room_id"].(string)
		if roomID == "" {
			return "", fmt.Errorf("room_id required")
		}
		return postJSON(client, fmt.Sprintf("%s/api/v1/rooms/%s/join", daemonURL, roomID), map[string]interface{}{
			"did": args["did"],
		})

	case "chat.room.leave":
		roomID, _ := args["room_id"].(string)
		if roomID == "" {
			return "", fmt.Errorf("room_id required")
		}
		return postJSON(client, fmt.Sprintf("%s/api/v1/rooms/%s/leave", daemonURL, roomID), map[string]interface{}{
			"did": args["did"],
		})

	case "chat.message.send":
		roomID, _ := args["room_id"].(string)
		if roomID == "" {
			return "", fmt.Errorf("room_id required")
		}
		return postJSON(client, fmt.Sprintf("%s/api/v1/rooms/%s/messages", daemonURL, roomID), args)

	case "chat.history.fetch":
		roomID, _ := args["room_id"].(string)
		limit := args["limit"]
		url := fmt.Sprintf("%s/api/v1/rooms/%s/messages", daemonURL, roomID)
		if limit != nil {
			url = fmt.Sprintf("%s?limit=%v", url, limit)
		}
		res, err := client.Get(url)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return string(body), nil

	case "chat.buddy.request":
		return postJSON(client, daemonURL+"/api/v1/buddies/request", args)

	case "chat.buddy.accept":
		return postJSON(client, daemonURL+"/api/v1/buddies/accept", args)

	case "chat.buddy.block":
		return postJSON(client, daemonURL+"/api/v1/buddies/block", args)

	case "chat.auth.challenge":
		return postJSON(client, daemonURL+"/api/v1/auth/challenge", map[string]interface{}{})

	case "chat.auth.verify":
		return postJSON(client, daemonURL+"/api/v1/auth/verify", args)

	case "chat.config.get":
		res, err := client.Get(daemonURL + "/api/v1/config/security")
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return string(body), nil

	case "chat.config.security":
		return postJSON(client, daemonURL+"/api/v1/config/security", args)

	default:
		return "", fmt.Errorf("unknown tool: %s", toolName)
	}
}

func postJSON(client *http.Client, url string, payload interface{}) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	res, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return "", fmt.Errorf("daemon error (%d): %s", res.StatusCode, string(body))
	}
	return string(body), nil
}

func getToolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "chat.health",
			Description: "Inspect the ACR Mesh health status, latency, connected agents, and audit chain depth.",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			Name:        "chat.rooms.list",
			Description: "List all active ACR deliberation channels.",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			Name:        "chat.room.create",
			Description: "Create a new agent deliberation room.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name":        map[string]string{"type": "string"},
					"description": map[string]string{"type": "string"},
					"topic":       map[string]string{"type": "string"},
					"is_private":  map[string]string{"type": "boolean"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "chat.room.join",
			Description: "Join an ACR deliberation room by DID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"room_id": map[string]string{"type": "string"},
					"did":     map[string]string{"type": "string"},
				},
				"required": []string{"room_id", "did"},
			},
		},
		{
			Name:        "chat.room.leave",
			Description: "Leave an ACR deliberation room by DID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"room_id": map[string]string{"type": "string"},
					"did":     map[string]string{"type": "string"},
				},
				"required": []string{"room_id", "did"},
			},
		},
		{
			Name:        "chat.message.send",
			Description: "Send an agent message with optional typed MCP tool payload to an ACR room.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"room_id":    map[string]string{"type": "string"},
					"sender_did": map[string]string{"type": "string"},
					"content":    map[string]string{"type": "string"},
				},
				"required": []string{"room_id", "sender_did", "content"},
			},
		},
		{
			Name:        "chat.history.fetch",
			Description: "Fetch previous message history from an ACR room.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"room_id": map[string]string{"type": "string"},
					"limit":   map[string]string{"type": "integer"},
				},
				"required": []string{"room_id"},
			},
		},
		{
			Name:        "chat.buddy.request",
			Description: "Send a buddy request to another agent DID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"from_did": map[string]string{"type": "string"},
					"to_did":   map[string]string{"type": "string"},
				},
				"required": []string{"from_did", "to_did"},
			},
		},
		{
			Name:        "chat.buddy.accept",
			Description: "Accept a pending buddy request from another agent DID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"from_did": map[string]string{"type": "string"},
					"to_did":   map[string]string{"type": "string"},
				},
				"required": []string{"from_did", "to_did"},
			},
		},
		{
			Name:        "chat.buddy.block",
			Description: "Block an agent DID from messaging or interacting with you.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"from_did": map[string]string{"type": "string"},
					"to_did":   map[string]string{"type": "string"},
				},
				"required": []string{"from_did", "to_did"},
			},
		},
		{
			Name:        "chat.auth.challenge",
			Description: "Request a cryptographic challenge nonce for DID authentication.",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			Name:        "chat.auth.verify",
			Description: "Verify a signed challenge nonce and register an agent DID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"did":          map[string]string{"type": "string"},
					"name":         map[string]string{"type": "string"},
					"role":         map[string]string{"type": "string"},
					"capabilities": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					"nonce":        map[string]string{"type": "string"},
					"signature":    map[string]string{"type": "string"},
				},
				"required": []string{"did", "name", "nonce", "signature"},
			},
		},
		{
			Name:        "chat.config.get",
			Description: "Inspect ACR Daemon active security configuration, Private Network Access (PNA), CORS, and version.",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			Name:        "chat.config.security",
			Description: "Dynamically configure Private Network Access (PNA) and Cross-Origin Resource Sharing (CORS) on the ACR daemon.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"enable_cors": map[string]string{"type": "boolean"},
					"enable_pna":  map[string]string{"type": "boolean"},
				},
			},
		},
	}
}

func sendResult(id interface{}, result interface{}) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}

func sendError(id interface{}, code int, message string) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
	data, _ := json.Marshal(resp)
	fmt.Println(string(data))
}
