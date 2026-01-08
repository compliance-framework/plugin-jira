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
	data.Set("scope", "read:jira-user read:jira-work read:workflow:jira read:permission:jira read:workflow-scheme:jira read:audit-log:jira read:avatar:jira read:group:jira read:issue-type:jira read:project-category:jira read:project:jira read:user:jira read:application-role:jira read:servicedesk-request")
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
	var allProjects []JiraProject
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters and expand to include lead
		url := fmt.Sprintf("/rest/api/3/project/search?startAt=%d&maxResults=%d&expand=lead", startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
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

		// Add current page results to all projects
		allProjects = append(allProjects, searchResp.Values...)
		c.Logger.Debug("Fetched projects page", "startAt", startAt, "count", len(searchResp.Values), "total", searchResp.Total)

		// Check if this is the last page
		if searchResp.IsLast || len(searchResp.Values) == 0 {
			break
		}

		// Move to next page
		startAt += len(searchResp.Values)
	}

	c.Logger.Debug("Fetched all projects", "total", len(allProjects))
	return allProjects, nil
}

func (c *Client) FetchWorkflowCapabilities(ctx context.Context, workflowID string) (*JiraWorkflowCapabilities, error) {
	url := fmt.Sprintf("/rest/api/3/workflows/capabilities?workflowId=%s", workflowID)
	resp, err := c.do(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.logSuccessOrWarn("FetchWorkflowCapabilities", resp, err)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var capabilities JiraWorkflowCapabilities
	if err := json.NewDecoder(resp.Body).Decode(&capabilities); err != nil {
		return nil, err
	}

	c.Logger.Debug("Fetched workflow capabilities", "workflowId", workflowID)
	return &capabilities, nil
}

func (c *Client) FetchWorkflows(ctx context.Context) ([]JiraWorkflow, error) {
	var allWorkflows []JiraWorkflow
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters and expand to include transitions
		url := fmt.Sprintf("/rest/api/3/workflows/search?startAt=%d&maxResults=%d&expand=values.transitions", startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
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

		// Add current page results to all workflows
		allWorkflows = append(allWorkflows, searchResp.Values...)
		c.Logger.Debug("Fetched workflows page", "startAt", startAt, "count", len(searchResp.Values), "total", searchResp.Total)

		// Check if this is the last page
		if searchResp.IsLast || len(searchResp.Values) == 0 {
			break
		}

		// Move to next page
		startAt += len(searchResp.Values)
	}

	c.Logger.Debug("Fetched all workflows", "total", len(allWorkflows))
	return allWorkflows, nil
}

func (c *Client) FetchWorkflowSchemes(ctx context.Context) ([]JiraWorkflowScheme, error) {
	var allWorkflowSchemes []JiraWorkflowScheme
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters
		url := fmt.Sprintf("/rest/api/3/workflowscheme?startAt=%d&maxResults=%d", startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
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

		// Add current page results to all workflow schemes
		allWorkflowSchemes = append(allWorkflowSchemes, searchResp.Values...)
		c.Logger.Debug("Fetched workflow schemes page", "startAt", startAt, "count", len(searchResp.Values), "total", searchResp.Total)

		// Check if this is the last page
		if searchResp.IsLast || len(searchResp.Values) == 0 {
			break
		}

		// Move to next page
		startAt += len(searchResp.Values)
	}

	c.Logger.Debug("Fetched all workflow schemes", "total", len(allWorkflowSchemes))
	return allWorkflowSchemes, nil
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
	var allSLAs []JiraSLA
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters
		url := fmt.Sprintf("/rest/servicedeskapi/request/%s/sla?startAt=%d&maxResults=%d", issueKey, startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
		if err != nil {
			c.Logger.Error("Error fetching SLAs", "issue", issueKey, "error", err)
			return nil, err
		}
		defer resp.Body.Close()
		c.logSuccessOrWarn("FetchIssueSLAs", resp, err)

		// Read the response body for debugging
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			c.Logger.Error("Error reading SLA response body", "issue", issueKey, "error", err)
			return nil, err
		}

		var result struct {
			Values     []JiraSLA `json:"values"`
			StartAt    int       `json:"startAt"`
			MaxResults int       `json:"maxResults"`
			Total      int       `json:"total"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			c.Logger.Error("Error unmarshaling SLA response", "issue", issueKey, "error", err, "body", string(body))
			return nil, err
		}

		// Add current page results to all SLAs
		allSLAs = append(allSLAs, result.Values...)
		c.Logger.Debug("Fetched SLAs page", "issue", issueKey, "startAt", startAt, "count", len(result.Values), "total", result.Total)

		// Check if this is the last page
		if len(result.Values) == 0 || startAt+len(result.Values) >= result.Total {
			break
		}

		// Move to next page
		startAt += len(result.Values)
	}

	return allSLAs, nil
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

func (c *Client) SearchChangeRequests(ctx context.Context, projectKeys []string, issueTypes []string) ([]JiraIssue, error) {
	// Build JQL query for issue types
	var issueTypeFilter string
	if len(issueTypes) > 0 {
		// Build issue type filter: issuetype in ('Type1', 'Type2', 'Type3')
		issueTypeFilter = "issuetype in ("
		for i, issueType := range issueTypes {
			if i > 0 {
				issueTypeFilter += ", "
			}
			issueTypeFilter += fmt.Sprintf("'%s'", issueType)
		}
		issueTypeFilter += ")"
	} else {
		// Fallback to default if no issue types provided
		issueTypeFilter = "issuetype in ('Change Request', 'Change')"
	}

	jql := fmt.Sprintf("%s AND status != 'Draft'", issueTypeFilter)

	// Add project filter if project keys are specified
	if len(projectKeys) > 0 {
		c.Logger.Debug("<<SearchChangeRequests>> Filtering by project keys", "projectKeys", projectKeys)
		// Build project filter: project in (KEY1, KEY2, KEY3)
		projectFilter := "project in ("
		for i, key := range projectKeys {
			if i > 0 {
				projectFilter += ", "
			}
			projectFilter += fmt.Sprintf("'%s'", key)
		}
		projectFilter += ")"
		jql = fmt.Sprintf("%s AND %s", projectFilter, jql)
	}

	var allIssues []JiraIssue
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		query := url.Values{}
		query.Set("jql", jql)
		query.Set("expand", "changelog")
		query.Set("fields", "project,issuetype,status,summary,description,reporter,assignee,priority,created,updated,duedate,environment,approvals")
		query.Set("startAt", fmt.Sprintf("%d", startAt))
		query.Set("maxResults", fmt.Sprintf("%d", maxResults))

		resp, err := c.do(ctx, "GET", "/rest/api/3/search/jql?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		c.logSuccessOrWarn("SearchChangeRequests", resp, err)

		var result struct {
			Issues     []JiraIssue `json:"issues"`
			StartAt    int         `json:"startAt"`
			MaxResults int         `json:"maxResults"`
			Total      int         `json:"total"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}

		// Add current page results to all issues
		allIssues = append(allIssues, result.Issues...)
		c.Logger.Debug("Searched change requests page", "startAt", startAt, "count", len(result.Issues), "total", result.Total)

		// Check if this is the last page
		if len(result.Issues) == 0 || startAt+len(result.Issues) >= result.Total {
			break
		}

		// Move to next page
		startAt += len(result.Issues)
	}

	c.Logger.Debug("Searched all change requests", "total", len(allIssues))
	return allIssues, nil
}

func (c *Client) FetchIssueChangelog(ctx context.Context, issueKey string) ([]JiraChangelogEntry, error) {
	var allEntries []JiraChangelogEntry
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters
		url := fmt.Sprintf("/rest/api/3/issue/%s/changelog?startAt=%d&maxResults=%d", issueKey, startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		c.logSuccessOrWarn("FetchIssueChangelog", resp, err)

		var result struct {
			Values     []JiraChangelogEntry `json:"values"`
			StartAt    int                  `json:"startAt"`
			MaxResults int                  `json:"maxResults"`
			Total      int                  `json:"total"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}

		// Add current page results to all entries
		allEntries = append(allEntries, result.Values...)
		c.Logger.Debug("Fetched changelog page", "issue", issueKey, "startAt", startAt, "count", len(result.Values), "total", result.Total)

		// Check if this is the last page
		if len(result.Values) == 0 || startAt+len(result.Values) >= result.Total {
			break
		}

		// Move to next page
		startAt += len(result.Values)
	}

	return allEntries, nil
}

func (c *Client) FetchIssueApprovals(ctx context.Context, issueKey string) ([]JiraApproval, error) {
	var allApprovals []JiraApproval
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters
		url := fmt.Sprintf("/rest/servicedeskapi/request/%s/approval?startAt=%d&maxResults=%d", issueKey, startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		c.logSuccessOrWarn("FetchIssueApprovals", resp, err)

		var result struct {
			Values     []JiraApproval `json:"values"`
			StartAt    int            `json:"startAt"`
			MaxResults int            `json:"maxResults"`
			Total      int            `json:"total"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}

		// Add current page results to all approvals
		allApprovals = append(allApprovals, result.Values...)
		c.Logger.Debug("Fetched approvals page", "issue", issueKey, "startAt", startAt, "count", len(result.Values), "total", result.Total)

		// Check if this is the last page
		if len(result.Values) == 0 || startAt+len(result.Values) >= result.Total {
			break
		}

		// Move to next page
		startAt += len(result.Values)
	}

	return allApprovals, nil
}

func (c *Client) FetchProjectRemoteLinks(ctx context.Context, projectKey string) ([]JiraRemoteLink, error) {
	// Placeholder as requested in original code
	return nil, nil
}

func (c *Client) GetAllStatuses(ctx context.Context) ([]JiraStatus, error) {
	var allStatuses []JiraStatus
	startAt := 0
	maxResults := 50 // Jira default max per page

	for {
		// Build URL with pagination parameters
		url := fmt.Sprintf("/rest/api/3/statuses/search?startAt=%d&maxResults=%d", startAt, maxResults)
		resp, err := c.do(ctx, "GET", url, nil)
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

		// Add current page results to all statuses
		allStatuses = append(allStatuses, searchResp.Values...)
		c.Logger.Debug("Fetched statuses page", "startAt", startAt, "count", len(searchResp.Values), "total", searchResp.Total)

		// Check if this is the last page
		if searchResp.IsLast || len(searchResp.Values) == 0 {
			break
		}

		// Move to next page
		startAt += len(searchResp.Values)
	}

	c.Logger.Debug("Fetched all statuses", "total", len(allStatuses))
	return allStatuses, nil
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

// GetWorkflowSchemesForProjects retrieves workflow schemes for specific project IDs
func (c *Client) GetWorkflowSchemesForProjects(ctx context.Context, projectIds []int64) ([]JiraWorkflowScheme, error) {
	associations, err := c.GetWorkflowSchemeProjectAssociations(ctx, projectIds)
	if err != nil {
		return nil, err
	}

	// Extract unique workflow scheme IDs
	schemeIDs := make(map[int64]bool)
	for _, assoc := range associations {
		schemeIDs[assoc.WorkflowScheme.ID] = true
	}

	// Fetch all workflow schemes
	allSchemes, err := c.FetchWorkflowSchemes(ctx)
	if err != nil {
		return nil, err
	}

	// Filter schemes that are associated with the projects
	var filteredSchemes []JiraWorkflowScheme
	for _, scheme := range allSchemes {
		if schemeIDs[scheme.ID] {
			filteredSchemes = append(filteredSchemes, scheme)
		}
	}

	return filteredSchemes, nil
}

// GetWorkflowsForWorkflowSchemes retrieves workflows for specific workflow schemes
func (c *Client) GetWorkflowsForWorkflowSchemes(ctx context.Context, workflowSchemes []JiraWorkflowScheme) ([]JiraWorkflow, error) {
	// Get all workflows
	allWorkflows, err := c.FetchWorkflows(ctx)
	if err != nil {
		return nil, err
	}

	// Create a map of workflow names from schemes
	workflowNames := make(map[string]bool)
	for _, scheme := range workflowSchemes {
		// Add default workflow
		if scheme.DefaultWorkflow != "" {
			workflowNames[scheme.DefaultWorkflow] = true
		}
		// Add workflows from issue type mappings
		for _, workflowName := range scheme.IssueTypeMappings {
			workflowNames[workflowName] = true
		}
	}

	// Filter workflows that are referenced in the schemes
	var filteredWorkflows []JiraWorkflow
	for _, workflow := range allWorkflows {
		if workflowNames[workflow.Name] {
			filteredWorkflows = append(filteredWorkflows, workflow)
		}
	}

	return filteredWorkflows, nil
}
