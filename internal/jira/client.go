package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/go-hclog"
)

// Client handles communication with Jira APIs
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Logger     hclog.Logger
}

func NewClient(baseURL string, httpClient *http.Client, logger hclog.Logger) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Logger:     logger,
	}
}

type tokenAuthTransport struct {
	email string
	token string
	base  http.RoundTripper
}

func (t *tokenAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(t.email, t.token)
	return t.base.RoundTrip(req)
}

func NewTokenAuthClient(email, token string) *http.Client {
	return &http.Client{
		Transport: &tokenAuthTransport{
			email: email,
			token: token,
			base:  http.DefaultTransport,
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.BaseURL)
	u = u.ResolveReference(rel)

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.HTTPClient.Do(req)
}

func (c *Client) FetchProjects(ctx context.Context) ([]JiraProject, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/project", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var projects []JiraProject
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func (c *Client) FetchWorkflows(ctx context.Context) ([]JiraWorkflow, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/workflow/search", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Values []JiraWorkflow `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Values, nil
}

func (c *Client) FetchWorkflowSchemes(ctx context.Context) ([]JiraWorkflowScheme, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/workflowscheme", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Values []JiraWorkflowScheme `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Values, nil
}

func (c *Client) FetchIssueTypes(ctx context.Context) ([]JiraIssueType, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/issuetype", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var types []JiraIssueType
	if err := json.NewDecoder(resp.Body).Decode(&types); err != nil {
		return nil, err
	}
	return types, nil
}

func (c *Client) FetchFields(ctx context.Context) ([]JiraField, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/field", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var fields []JiraField
	if err := json.NewDecoder(resp.Body).Decode(&fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func (c *Client) FetchAuditRecords(ctx context.Context) ([]JiraAuditRecord, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/auditing/record", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Records []JiraAuditRecord `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Records, nil
}

func (c *Client) FetchGlobalPermissions(ctx context.Context) ([]JiraPermission, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/permissions", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Permissions map[string]JiraPermission `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	perms := make([]JiraPermission, 0, len(result.Permissions))
	for _, p := range result.Permissions {
		perms = append(perms, p)
	}
	return perms, nil
}

func (c *Client) FetchIssueSLAs(ctx context.Context, issueKey string) ([]JiraSLA, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/rest/servicedeskapi/request/%s/sla", issueKey), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Values []JiraSLA `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Values, nil
}

func (c *Client) FetchIssueDevInfo(ctx context.Context, issueKey string) (*JiraDevInfo, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/rest/devinfo/0.10/bulk?issueKeys=%s", issueKey), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info JiraDevInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Client) FetchIssueDeployments(ctx context.Context, issueKey string) ([]JiraDeployment, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/rest/deployments/0.1/bulk?issueKeys=%s", issueKey), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Deployments []JiraDeployment `json:"deployments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Deployments, nil
}

func (c *Client) SearchChangeRequests(ctx context.Context) ([]JiraIssue, error) {
	jql := "issuetype in ('Change Request', 'Change') AND status != 'Draft'"
	query := url.Values{}
	query.Set("jql", jql)
	query.Set("expand", "changelog")

	resp, err := c.do(ctx, "GET", "/rest/api/3/search?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Issues []JiraIssue `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Issues, nil
}

func (c *Client) FetchIssueChangelog(ctx context.Context, issueKey string) ([]JiraChangelogEntry, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/rest/api/3/issue/%s/changelog", issueKey), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Values []JiraChangelogEntry `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Values, nil
}

func (c *Client) FetchIssueApprovals(ctx context.Context, issueKey string) ([]JiraApproval, error) {
	resp, err := c.do(ctx, "GET", fmt.Sprintf("/rest/servicedeskapi/request/%s/approval", issueKey), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Values []JiraApproval `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Values, nil
}

func (c *Client) FetchProjectRemoteLinks(ctx context.Context, projectKey string) ([]JiraRemoteLink, error) {
	// Placeholder as requested in original code
	return nil, nil
}
