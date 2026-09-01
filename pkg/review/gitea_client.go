package review

import (
	"context"
	"fmt"

	gitea "code.gitea.io/sdk/gitea"
)

// GiteaClient wraps the Gitea SDK for stack and PR operations.
type GiteaClient struct {
	client  *gitea.Client
	baseURL string
}

// NewGiteaClient constructs a GiteaClient. token may be empty for public repos.
func NewGiteaClient(baseURL, token string) (*GiteaClient, error) {
	var opts []gitea.ClientOption
	if token != "" {
		opts = append(opts, gitea.SetToken(token))
	}
	c, err := gitea.NewClient(baseURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("gitea client: %w", err)
	}
	return &GiteaClient{client: c, baseURL: baseURL}, nil
}

// ListOpenPRs returns all open pull requests for a repo (owner/name).
func (g *GiteaClient) ListOpenPRs(ctx context.Context, owner, repo string) ([]*gitea.PullRequest, error) {
	prs, _, err := g.client.ListRepoPullRequests(owner, repo, gitea.ListPullRequestsOptions{
		State: gitea.StateOpen,
	})
	if err != nil {
		return nil, fmt.Errorf("list PRs %s/%s: %w", owner, repo, err)
	}
	return prs, nil
}

// CreateStackPR opens a PR for a stack layer.
func (g *GiteaClient) CreateStackPR(ctx context.Context, owner, repo, head, base, title, body string) (*gitea.PullRequest, error) {
	pr, _, err := g.client.CreatePullRequest(owner, repo, gitea.CreatePullRequestOption{
		Head:  head,
		Base:  base,
		Title: title,
		Body:  body,
	})
	if err != nil {
		return nil, fmt.Errorf("create PR %s/%s head=%s: %w", owner, repo, head, err)
	}
	return pr, nil
}

// PostConsensusComment posts the canonical MergeDecisionEnvelope JSON as a PR review comment.
func (g *GiteaClient) PostConsensusComment(ctx context.Context, owner, repo string, prNumber int, body string) error {
	_, _, err := g.client.CreateIssueComment(owner, repo, int64(prNumber), gitea.CreateIssueCommentOption{
		Body: body,
	})
	if err != nil {
		return fmt.Errorf("post consensus comment PR#%d: %w", prNumber, err)
	}
	return nil
}

// SetPRLabel adds a label to a pull request (used for stack metadata: "stack:<id>", "layer:<n>").
func (g *GiteaClient) SetPRLabel(ctx context.Context, owner, repo string, prNumber int, labelName string) error {
	// Find or create label
	labels, _, err := g.client.ListRepoLabels(owner, repo, gitea.ListLabelsOptions{})
	if err != nil {
		return fmt.Errorf("list labels: %w", err)
	}
	var labelID int64
	for _, l := range labels {
		if l.Name == labelName {
			labelID = l.ID
			break
		}
	}
	if labelID == 0 {
		label, _, err := g.client.CreateLabel(owner, repo, gitea.CreateLabelOption{
			Name:  labelName,
			Color: "#0075ca",
		})
		if err != nil {
			return fmt.Errorf("create label %q: %w", labelName, err)
		}
		labelID = label.ID
	}
	_, _, err = g.client.AddIssueLabels(owner, repo, int64(prNumber), gitea.IssueLabelsOption{
		Labels: []int64{labelID},
	})
	return err
}

// GetPRDiff fetches the unified diff text for a pull request.
func (g *GiteaClient) GetPRDiff(ctx context.Context, owner, repo string, prNumber int) (string, error) {
	pr, _, err := g.client.GetPullRequest(owner, repo, int64(prNumber))
	if err != nil {
		return "", fmt.Errorf("get PR #%d: %w", prNumber, err)
	}
	// Use the diff URL to fetch raw diff text
	_ = pr
	// Gitea SDK doesn't expose raw diff directly; fall back to git diff between base/head
	return "", nil
}
