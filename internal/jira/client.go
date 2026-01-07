package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// Client handles communication with Jira APIs
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Logger     hclog.Logger
	CloudID    string
}

func NewClient(baseURL string, httpClient *http.Client, logger hclog.Logger) (*Client, error) {
	// First, fetch the Cloud ID
	cloudID, err := fetchCloudID(baseURL)
	if err != nil {
		logger.Error("Failed to fetch Cloud ID", "error", err)
		return nil, fmt.Errorf("failed to fetch Cloud ID: %w", err)
	}

	logger.Debug("Got Cloud ID", "cloudID", cloudID)

	return &Client{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Logger:     logger,
		CloudID:    cloudID,
	}, nil
}

func fetchCloudID(baseURL string) (string, error) {
	// Make request to get tenant info
	resp, err := http.Get(baseURL + "/_edge/tenant_info")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get tenant info: %d", resp.StatusCode)
	}

	var result struct {
		CloudID string `json:"cloudId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode tenant info: %w", err)
	}

	if result.CloudID == "" {
		return "", fmt.Errorf("no Cloud ID found in tenant info")
	}

	return result.CloudID, nil
}

type oauth2Transport struct {
	base     http.RoundTripper
	logger   hclog.Logger
	tokenURL string
	clientID string
	secret   string
	resource string
}

func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get OAuth2 token with required scopes
	tokenReq, err := http.NewRequest("POST", t.tokenURL, nil)
	if err != nil {
		return nil, err
	}
	tokenReq.SetBasicAuth(t.clientID, t.secret)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Form encode the parameters
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "read:jira-user read:jira-work read:workflow:jira read:permission:jira read:workflow-scheme:jira read:audit-log:jira read:avatar:jira read:group:jira read:issue-type:jira read:project-category:jira read:project:jira read:user:jira read:application-role:jira")
	tokenReq.Body = io.NopCloser(strings.NewReader(data.Encode()))

	resp, err := t.base.RoundTrip(tokenReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get token: %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w, body: %s", err, string(body))
	}
	t.logger.Debug("Got OAuth2 token", "scope", tokenResp.Scope, "expiresIn", tokenResp.ExpiresIn)

	// Clone the request and set the bearer token
	newReq := req.Clone(req.Context())
	newReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	t.logger.Debug("Making request with Bearer token", "url", newReq.URL.String(), "auth", "Bearer "+tokenResp.AccessToken[:10]+"...")
	return t.base.RoundTrip(newReq)
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

func (c *Client) logSuccessOrWarn(request string, resp *http.Response, err error) {
	if err != nil {
		c.Logger.Warn("<<<FAIL>>> Fail with the request", "request", request, "error", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.Logger.Warn("<<<FAIL>>> Request status code != 200", "request", request, "status code", resp.StatusCode, "body", string(body))
		return
	}
	c.Logger.Info("<<<SUCCESS>>> Request Successful! ", "request", request)
}
func NewOAuth2Client(clientID, clientSecret, baseURL string, logger hclog.Logger) *http.Client {
	return &http.Client{
		Transport: &oauth2Transport{
			base:     http.DefaultTransport,
			tokenURL: "https://auth.atlassian.com/oauth/token",
			clientID: clientID,
			secret:   clientSecret,
			resource: "api.atlassian.com",
			logger:   logger,
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	// Use the correct API endpoint format: https://api.atlassian.com/ex/jira/<cloudId>/rest/api/3/...
	apiURL := fmt.Sprintf("https://api.atlassian.com/ex/jira/%s%s", c.CloudID, path)
	c.Logger.Debug("Requesting", "method", method, "url", apiURL)

	req, err := http.NewRequestWithContext(ctx, method, apiURL, body)
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
	resp, err := c.do(ctx, "GET", "/rest/api/3/project/search", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("FetchProjects", resp, err)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	body := resp.Body
	var searchResp JiraProjectSearchResponse
	if err := json.NewDecoder(body).Decode(&searchResp); err != nil {
		return nil, err
	}
	c.Logger.Debug("Fetched projects", "status", resp.StatusCode, "total", searchResp.Total, "projects", len(searchResp.Values))
	return searchResp.Values, nil
}

func (c *Client) FetchWorkflows(ctx context.Context) ([]JiraWorkflow, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/workflows/search", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("FetchWorkflows", resp, err)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var searchResp JiraWorkflowSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}
	c.Logger.Debug("Fetched workflows", "status", resp.StatusCode, "total", searchResp.Total, "workflows", len(searchResp.Values))
	return searchResp.Values, nil
}

func (c *Client) FetchWorkflowSchemes(ctx context.Context) ([]JiraWorkflowScheme, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/workflowscheme", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("FetchWorkflowSchemes", resp, err)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var searchResp JiraWorkflowSchemeSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}
	c.Logger.Debug("Fetched workflow schemes", "status", resp.StatusCode, "total", searchResp.Total, "schemes", len(searchResp.Values))
	return searchResp.Values, nil
}

func (c *Client) FetchIssueTypes(ctx context.Context) ([]JiraIssueType, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/issuetype", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("FetchIssueTypes", resp, err)
	var types []JiraIssueType
	if err := json.NewDecoder(resp.Body).Decode(&types); err != nil {
		return nil, err
	}
	c.Logger.Debug("<<<SUCCESS!!>>> Got Issue Types")
	return types, nil
}

func (c *Client) FetchFields(ctx context.Context) ([]JiraField, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/field", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("FetchFields", resp, err)
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
	c.logSuccessOrWarn("FetchAuditRecords", resp, err)

	// Read the raw response for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("Raw audit records response", "body", string(body))

	var result struct {
		Records []JiraAuditRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
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
	c.logSuccessOrWarn("FetchGlobalPermissions", resp, err)

	var result JiraPermissionsResponse
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
	c.logSuccessOrWarn("FetchIssueSLAs", resp, err)
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
	c.logSuccessOrWarn("FetchIssueDevInfo", resp, err)
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
	c.logSuccessOrWarn("FetchIssueDeployments", resp, err)
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

	resp, err := c.do(ctx, "GET", "/rest/api/3/search/jql?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("SearchChangeRequests", resp, err)
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
	c.logSuccessOrWarn("FetchIssueChangelog", resp, err)
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
	c.logSuccessOrWarn("FetchIssueApprovals", resp, err)
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

func (c *Client) GetAllStatuses(ctx context.Context) ([]JiraStatus, error) {
	resp, err := c.do(ctx, "GET", "/rest/api/3/statuses/search", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("GetAllStatuses", resp, err)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var searchResp JiraStatusSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	c.Logger.Debug("Fetched all statuses", "status", resp.StatusCode, "total", searchResp.Total, "statuses", len(searchResp.Values))
	return searchResp.Values, nil
}

func (c *Client) GetWorkflowSchemeProjectAssociations(ctx context.Context, projectIds []int64) ([]JiraWorkflowSchemeProjectAssociation, error) {
	// Build query parameters for project IDs
	if len(projectIds) == 0 {
		return nil, fmt.Errorf("at least one project ID is required")
	}

	// Convert project IDs to query parameters
	params := url.Values{}
	for _, id := range projectIds {
		params.Add("projectId", fmt.Sprintf("%d", id))
	}

	url := fmt.Sprintf("/rest/api/3/workflowscheme/project?%s", params.Encode())
	resp, err := c.do(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("GetWorkflowSchemeProjectAssociations", resp, err)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result JiraWorkflowSchemeProjectAssociationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	c.Logger.Debug("Fetched workflow scheme project associations", "status", resp.StatusCode, "associations", len(result.Values))
	return result.Values, nil
}
