package mcp

import (
	"path/filepath"
	"testing"

	"acr-core/pkg/governance"
	"acr-core/pkg/models"
)

type noopBroadcaster struct{}

func (n *noopBroadcaster) BroadcastMessage(msg *models.Message) error    { return nil }
func (n *noopBroadcaster) BroadcastAgentUpdate(agent *models.Agent) error { return nil }

func newTestServer() *Server {
	gov := governance.NewEngine(nil, nil)
	return NewServer(gov, &noopBroadcaster{})
}

func TestRegisterAndGetAgents(t *testing.T) {
	s := newTestServer()

	agent, err := s.Register("did:key:z6Mkabc", "TestBot", "", "agent", "TestOrg", []string{"chat.*"})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if agent.Name != "TestBot" {
		t.Errorf("expected name TestBot, got %s", agent.Name)
	}
	if agent.Status != models.StatusOnline {
		t.Errorf("expected online status, got %s", agent.Status)
	}

	agents := s.GetAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
}

func TestRegisterInvalidDID(t *testing.T) {
	s := newTestServer()
	_, err := s.Register("invalid-did", "Bot", "", "agent", "", nil)
	if err == nil {
		t.Error("expected error for invalid DID")
	}
}

func TestChallengeResponseAuth(t *testing.T) {
	s := newTestServer()

	// Step 1: Create challenge
	challenge, err := s.CreateChallenge()
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	if challenge.Nonce == "" {
		t.Error("expected non-empty nonce")
	}

	// Step 2: Verify with signed response
	agent, err := s.VerifyAndRegister(models.AuthVerifyRequest{
		DID:          "did:key:z6Mktest123",
		Name:         "AuthBot",
		Role:         "agent",
		Org:          "TestOrg",
		Capabilities: []string{"chat.*"},
		Nonce:        challenge.Nonce,
		Signature:    "mock-ed25519-signature",
	})
	if err != nil {
		t.Fatalf("VerifyAndRegister failed: %v", err)
	}
	if agent.Name != "AuthBot" {
		t.Errorf("expected AuthBot, got %s", agent.Name)
	}

	// Step 3: Reuse nonce should fail
	_, err = s.VerifyAndRegister(models.AuthVerifyRequest{
		DID:       "did:key:z6Mkother",
		Name:      "ReplayBot",
		Nonce:     challenge.Nonce,
		Signature: "sig",
	})
	if err == nil {
		t.Error("expected error for reused nonce")
	}
}

func TestChallengeResponseNoSignature(t *testing.T) {
	s := newTestServer()
	challenge, _ := s.CreateChallenge()

	_, err := s.VerifyAndRegister(models.AuthVerifyRequest{
		DID:   "did:key:z6Mknosig",
		Name:  "NoSigBot",
		Nonce: challenge.Nonce,
		// No signature
	})
	if err == nil {
		t.Error("expected error for missing signature")
	}
}

func TestSendMessageCapabilityGate(t *testing.T) {
	s := newTestServer()

	// Register agent with only k8s capabilities (no chat.*)
	_, _ = s.Register("did:key:z6Mklimited", "LimitedBot", "", "agent", "", []string{"k8s.deploy"})

	_, err := s.SendMessage("consensus-main", "did:key:z6Mklimited", "hello", nil)
	if err == nil {
		t.Error("expected capability gate to deny message from agent without chat.* capability")
	}
}

func TestSendMessageWithCapability(t *testing.T) {
	s := newTestServer()

	_, _ = s.Register("did:key:z6Mkchat", "ChatBot", "", "agent", "", []string{"chat.*"})

	msg, err := s.SendMessage("consensus-main", "did:key:z6Mkchat", "hello world", nil)
	if err != nil {
		t.Fatalf("expected message to succeed, got: %v", err)
	}
	if msg.Content != "hello world" {
		t.Errorf("expected content 'hello world', got %s", msg.Content)
	}
}

func TestSendMessageToNonexistentRoom(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkfoo", "Bot", "", "agent", "", []string{"chat.*"})

	_, err := s.SendMessage("nonexistent-room", "did:key:z6Mkfoo", "hello", nil)
	if err == nil {
		t.Error("expected error for nonexistent room")
	}
}

func TestRoomCreateJoinLeave(t *testing.T) {
	s := newTestServer()

	_, _ = s.Register("did:key:z6Mkuser1", "User1", "", "agent", "", []string{"chat.*"})

	// Create room
	room, err := s.CreateRoom("Test Room", "A test room", "Testing", false, "did:key:z6Mkuser1")
	if err != nil {
		t.Fatalf("CreateRoom failed: %v", err)
	}
	if room.ID != "test-room" {
		t.Errorf("expected room ID 'test-room', got %s", room.ID)
	}
	if len(room.Participants) != 1 {
		t.Errorf("expected 1 participant, got %d", len(room.Participants))
	}

	// Join room
	_, _ = s.Register("did:key:z6Mkuser2", "User2", "", "agent", "", []string{"chat.*"})
	err = s.JoinRoom("test-room", "did:key:z6Mkuser2")
	if err != nil {
		t.Fatalf("JoinRoom failed: %v", err)
	}

	rooms := s.GetRooms()
	var testRoom *models.Room
	for _, r := range rooms {
		if r.ID == "test-room" {
			testRoom = r
			break
		}
	}
	if testRoom == nil {
		t.Fatal("test-room not found")
	}
	if len(testRoom.Participants) != 2 {
		t.Errorf("expected 2 participants, got %d", len(testRoom.Participants))
	}

	// Leave room
	err = s.LeaveRoom("test-room", "did:key:z6Mkuser2")
	if err != nil {
		t.Fatalf("LeaveRoom failed: %v", err)
	}

	// Re-read
	for _, r := range s.GetRooms() {
		if r.ID == "test-room" {
			if len(r.Participants) != 1 {
				t.Errorf("expected 1 participant after leave, got %d", len(r.Participants))
			}
		}
	}
}

func TestRoomCreateDuplicate(t *testing.T) {
	s := newTestServer()
	_, _ = s.CreateRoom("Consensus Main", "desc", "", false, "did:key:z6Mkop")
	// consensus-main already exists from NewServer
	_, err := s.CreateRoom("Consensus Main", "desc2", "", false, "did:key:z6Mkop")
	if err == nil {
		t.Error("expected error for duplicate room creation")
	}
}

func TestBuddyRequestAcceptBlock(t *testing.T) {
	s := newTestServer()

	_, _ = s.Register("did:key:z6Mka", "Alice", "", "agent", "", []string{"chat.*"})
	_, _ = s.Register("did:key:z6Mkb", "Bob", "", "agent", "", []string{"chat.*"})

	// Request
	err := s.BuddyRequest("did:key:z6Mka", "did:key:z6Mkb")
	if err != nil {
		t.Fatalf("BuddyRequest failed: %v", err)
	}

	buddies := s.GetBuddies("did:key:z6Mka")
	if len(buddies) != 1 {
		t.Fatalf("expected 1 buddy relation, got %d", len(buddies))
	}
	if buddies[0].Status != models.BuddyPending {
		t.Errorf("expected pending status, got %s", buddies[0].Status)
	}

	// Accept (Bob accepts request from Alice)
	err = s.BuddyAccept("did:key:z6Mkb", "did:key:z6Mka")
	if err != nil {
		t.Fatalf("BuddyAccept failed: %v", err)
	}

	// Block
	err = s.BuddyBlock("did:key:z6Mkb", "did:key:z6Mka")
	if err != nil {
		t.Fatalf("BuddyBlock failed: %v", err)
	}

	bobBuddies := s.GetBuddies("did:key:z6Mkb")
	hasBlock := false
	for _, rel := range bobBuddies {
		if rel.ToDID == "did:key:z6Mka" && rel.Status == models.BuddyBlocked {
			hasBlock = true
		}
	}
	if !hasBlock {
		t.Error("expected block relation to exist")
	}
}

func TestBuddyBlockPreventsMessage(t *testing.T) {
	s := newTestServer()

	_, _ = s.Register("did:key:z6Mkblocker", "Blocker", "", "agent", "", []string{"chat.*"})
	_, _ = s.Register("did:key:z6Mkblocked", "Blocked", "", "agent", "", []string{"chat.*"})

	// Blocker joins consensus-main
	_ = s.JoinRoom("consensus-main", "did:key:z6Mkblocker")

	// Block the other agent
	_ = s.BuddyBlock("did:key:z6Mkblocker", "did:key:z6Mkblocked")

	// Blocked agent tries to send a message
	_, err := s.SendMessage("consensus-main", "did:key:z6Mkblocked", "hello from blocked", nil)
	if err == nil {
		t.Error("expected blocked agent to be denied from sending to room")
	}
}

func TestBuddyRequestSelfDenied(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkself", "Self", "", "agent", "", nil)

	err := s.BuddyRequest("did:key:z6Mkself", "did:key:z6Mkself")
	if err == nil {
		t.Error("expected error for self buddy request")
	}
}

func TestFetchHistory(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkh", "HistBot", "", "agent", "", []string{"chat.*"})

	for i := 0; i < 10; i++ {
		s.SendMessage("consensus-main", "did:key:z6Mkh", "msg", nil)
	}

	msgs, _ := s.FetchHistory("consensus-main", 5)
	if len(msgs) != 5 {
		t.Errorf("expected 5 messages, got %d", len(msgs))
	}

	all, _ := s.FetchHistory("consensus-main", 0)
	if len(all) != 10 {
		t.Errorf("expected 10 messages with limit 0, got %d", len(all))
	}
}

func TestSetPresence(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkpres", "PresBot", "", "agent", "", nil)

	err := s.SetPresence("did:key:z6Mkpres", models.StatusAway)
	if err != nil {
		t.Fatalf("SetPresence failed: %v", err)
	}

	for _, a := range s.GetAgents() {
		if a.DID == "did:key:z6Mkpres" && a.Status != models.StatusAway {
			t.Errorf("expected away status, got %s", a.Status)
		}
	}
}

func TestHealth(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkh1", "Bot", "", "agent", "", nil)

	health := s.GetHealth()
	if health.Version != "v0.8.2-draft" {
		t.Errorf("expected version v0.8.2-draft, got %s", health.Version)
	}
	if health.AgentCount != 1 {
		t.Errorf("expected 1 agent, got %d", health.AgentCount)
	}
	if health.RoomCount != 2 {
		t.Errorf("expected 2 rooms (default), got %d", health.RoomCount)
	}
}

func TestSendMessageWithToolCall(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mktool", "ToolBot", "", "agent", "", []string{"chat.*"})

	toolCall := &models.McpToolCall{
		ID:        "tool-1",
		ToolName:  "mcp.ast_diff.verify",
		Arguments: map[string]interface{}{"pr_id": 42},
		Output:    "No issues found",
		Status:    "completed",
		LatencyMs: 1.23,
	}

	msg, err := s.SendMessage("consensus-main", "did:key:z6Mktool", "Verified PR #42", toolCall)
	if err != nil {
		t.Fatalf("SendMessage with tool call failed: %v", err)
	}
	if msg.ToolCall == nil {
		t.Error("expected tool call to be attached")
	}
	if msg.ToolCall.ToolName != "mcp.ast_diff.verify" {
		t.Errorf("expected tool name mcp.ast_diff.verify, got %s", msg.ToolCall.ToolName)
	}
}

func TestRateLimiter(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkrapid", "RapidBot", "", "agent", "", []string{"chat.*"})

	// Capacity is 20 tokens. First 20 should succeed.
	var err error
	for i := 0; i < 20; i++ {
		_, err = s.SendMessage("consensus-main", "did:key:z6Mkrapid", "rapid message", nil)
		if err != nil {
			t.Fatalf("expected message %d to succeed, got %v", i, err)
		}
	}

	// 21st immediate message must exceed rate limit
	_, err = s.SendMessage("consensus-main", "did:key:z6Mkrapid", "overflow message", nil)
	if err == nil {
		t.Error("expected rate limit error on 21st burst message")
	}
}

func TestRoomACL(t *testing.T) {
	s := newTestServer()
	_, _ = s.Register("did:key:z6Mkowner", "OwnerBot", "", "agent", "", []string{"chat.*"})
	_, _ = s.Register("did:key:z6Mkoutsider", "OutsiderBot", "", "agent", "", []string{"chat.*"})

	// Create private room with owner
	_, err := s.CreateRoom("Secret Room", "Top secret channel", "Confidential", true, "did:key:z6Mkowner")
	if err != nil {
		t.Fatalf("CreateRoom failed: %v", err)
	}

	// Outsider attempts to send message to private room -> denied
	_, err = s.SendMessage("secret-room", "did:key:z6Mkoutsider", "sneaking in", nil)
	if err == nil {
		t.Error("expected access denied for outsider in private room")
	}

	// Owner can send message
	_, err = s.SendMessage("secret-room", "did:key:z6Mkowner", "authorized message", nil)
	if err != nil {
		t.Errorf("expected owner to be permitted, got %v", err)
	}

	// After joining, outsider can send
	_ = s.JoinRoom("secret-room", "did:key:z6Mkoutsider")
	_, err = s.SendMessage("secret-room", "did:key:z6Mkoutsider", "now authorized", nil)
	if err != nil {
		t.Errorf("expected outsider to be permitted after joining, got %v", err)
	}
}

func TestPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	s1 := newTestServer()
	if err := s1.SetStateFilePath(statePath); err != nil {
		t.Fatalf("SetStateFilePath failed: %v", err)
	}

	_, _ = s1.Register("did:key:z6Mkpersist", "PersistBot", "avatar.png", "agent", "ACR", []string{"chat.*"})
	_, _ = s1.CreateRoom("Persist Room", "Room for persistence testing", "Testing", false, "did:key:z6Mkpersist")
	_, _ = s1.SendMessage("persist-room", "did:key:z6Mkpersist", "Saved message", nil)

	// Create brand new server pointing to the same file
	s2 := newTestServer()
	if err := s2.SetStateFilePath(statePath); err != nil {
		t.Fatalf("Failed to load persisted state in new server: %v", err)
	}

	// Verify agent restored
	agents := s2.GetAgents()
	foundAgent := false
	for _, a := range agents {
		if a.DID == "did:key:z6Mkpersist" {
			foundAgent = true
			break
		}
	}
	if !foundAgent {
		t.Error("expected persisted agent to be loaded in new server")
	}

	// Verify messages restored
	msgs, _ := s2.FetchHistory("persist-room", 10)
	if len(msgs) != 1 || msgs[0].Content != "Saved message" {
		t.Errorf("expected 1 restored message 'Saved message', got %v", msgs)
	}
}

func TestVotingAndDissent(t *testing.T) {
	s := newTestServer()

	_, _ = s.Register("did:key:z6Mkproposer", "ProposerBot", "", "agent", "", []string{"chat.*"})
	_, _ = s.Register("did:key:z6Mkyes", "YesBot", "", "agent", "", []string{"chat.*"})
	_, _ = s.Register("did:key:z6Mkdissent", "DissentBot", "", "agent", "", []string{"chat.*"})

	// 1. Create Proposal
	prop, err := s.CreateProposal(
		"consensus-main",
		"CIP-104: Merge AST Diff Engine",
		"Proposal to merge pull request #104 into main",
		"did:key:z6Mkproposer",
		[]string{"APPROVE", "REJECT", "DISSENT"},
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}
	if prop.Status != "open" {
		t.Errorf("expected open proposal status, got %s", prop.Status)
	}

	// 2. Cast Approve Vote
	_, err = s.CastVote(prop.ID, "did:key:z6Mkyes", "APPROVE", "")
	if err != nil {
		t.Fatalf("CastVote approve failed: %v", err)
	}

	// 3. Reject Dissent Vote without Rationale (GAP-08)
	_, err = s.CastVote(prop.ID, "did:key:z6Mkdissent_invalid", "DISSENT", "")
	if err == nil {
		t.Fatalf("expected CastVote to fail when DISSENT lacks rationale, got nil")
	}

	// 4. Cast Dissent Vote with Rationale (GAP-08)
	updated, err := s.CastVote(prop.ID, "did:key:z6Mkdissent", "DISSENT", "Concern regarding cross-room memory boundary leak in PR #104")
	if err != nil {
		t.Fatalf("CastVote dissent failed: %v", err)
	}
	if len(updated.DissentLogs) != 1 {
		t.Fatalf("expected 1 preserved dissent log, got %d", len(updated.DissentLogs))
	}
	if updated.DissentLogs[0].VoterDID != "did:key:z6Mkdissent" {
		t.Errorf("expected dissent voter did:key:z6Mkdissent, got %s", updated.DissentLogs[0].VoterDID)
	}

	// 4. Close Proposal
	closed, err := s.CloseProposal(prop.ID, "did:key:z6Mkproposer")
	if err != nil {
		t.Fatalf("CloseProposal failed: %v", err)
	}
	if closed.Status != "passed" {
		t.Errorf("expected passed status, got %s", closed.Status)
	}
	if closed.ClosedAt == nil {
		t.Error("expected non-nil closed_at timestamp")
	}
}

func TestFileUploadAndDownload(t *testing.T) {
	s := newTestServer()

	data := []byte("ACR AST diff binary representation v0.8.2")
	att, err := s.UploadFile("ast_diff.bin", "application/octet-stream", data)
	if err != nil {
		t.Fatalf("UploadFile failed: %v", err)
	}
	if att.Size != int64(len(data)) {
		t.Errorf("expected size %d, got %d", len(data), att.Size)
	}

	// Retrieve file
	retrievedAtt, retrievedData, err := s.GetFile(att.ID)
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}
	if retrievedAtt.Filename != "ast_diff.bin" {
		t.Errorf("expected filename ast_diff.bin, got %s", retrievedAtt.Filename)
	}
	if string(retrievedData) != string(data) {
		t.Errorf("expected retrieved data %q, got %q", string(data), string(retrievedData))
	}
}
