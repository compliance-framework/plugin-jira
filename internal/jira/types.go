package jira

import "time"

type JiraData struct {
	Projects          []JiraProject        `json:"projects"`
	Issues            []JiraIssue          `json:"issues"`
	Workflows         []JiraWorkflow       `json:"workflows"`
	WorkflowSchemes   []JiraWorkflowScheme `json:"workflow_schemes"`
	IssueTypes        []JiraIssueType      `json:"issue_types"`
	Fields            []JiraField          `json:"fields"`
	AuditRecords      []JiraAuditRecord    `json:"audit_records"`
	GlobalPermissions []JiraPermission     `json:"global_permissions"`
}

type JiraProject struct {
	ID             string                `json:"id"`
	Key            string                `json:"key"`
	Name           string                `json:"name"`
	Category       *JiraProjectCategory  `json:"projectCategory,omitempty"`
	Components     []JiraComponent       `json:"components,omitempty"`
	WorkflowScheme *JiraWorkflowScheme   `json:"workflow_scheme,omitempty"`
	Permissions    *JiraPermissionScheme `json:"permission_scheme,omitempty"`
	RemoteLinks    []JiraRemoteLink      `json:"remote_links"`
}

type JiraProjectCategory struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type JiraComponent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraWorkflow struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Statuses    []JiraStatus     `json:"statuses"`
	Transitions []JiraTransition `json:"transitions"`
}

type JiraStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraTransition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	To   string `json:"to"`
}

type JiraWorkflowScheme struct {
	ID       int64             `json:"id"`
	Name     string            `json:"name"`
	Mappings map[string]string `json:"issueTypeMappings"` // IssueType -> Workflow Name
	Default  string            `json:"defaultWorkflow"`
}

type JiraIssueType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraField struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"schema,omitempty"`
}

type JiraIssue struct {
	Key         string                 `json:"key"`
	Fields      map[string]interface{} `json:"fields"`
	Changelog   []JiraChangelogEntry   `json:"changelog"`
	Approvals   []JiraApproval         `json:"approvals"`
	SLAs        []JiraSLA              `json:"slas,omitempty"`
	DevInfo     *JiraDevInfo           `json:"dev_info,omitempty"`
	Deployments []JiraDeployment       `json:"deployments,omitempty"`
}

type JiraChangelogEntry struct {
	Author  string              `json:"author"`
	Created time.Time           `json:"created"`
	Items   []JiraChangelogItem `json:"items"`
}

type JiraChangelogItem struct {
	Field string `json:"field"`
	From  string `json:"fromString"`
	To    string `json:"toString"`
}

type JiraApproval struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Approvers []string  `json:"approvers"`
	Completed time.Time `json:"completed_date"`
}

type JiraSLA struct {
	Name      string    `json:"name"`
	Breached  bool      `json:"breached"`
	Remaining string    `json:"remaining_time"`
	Target    time.Time `json:"target_date"`
}

type JiraDevInfo struct {
	PullRequests []JiraPR `json:"pull_requests"`
}

type JiraPR struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

type JiraDeployment struct {
	ID          string    `json:"id"`
	Environment string    `json:"environment"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
}

type JiraRemoteLink struct {
	ID     int64 `json:"id"`
	Object struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	} `json:"object"`
}

type JiraAuditRecord struct {
	ID         int64     `json:"id"`
	Summary    string    `json:"summary"`
	Created    time.Time `json:"created"`
	AuthorName string    `json:"authorName"`
	Category   string    `json:"category"`
}

type JiraPermission struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type JiraPermissionScheme struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
