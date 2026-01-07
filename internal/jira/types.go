package jira

import (
	"encoding/json"
	"strings"
	"time"
)

// JiraAuditTime handles the custom timestamp format used in JIRA audit records
type JiraAuditTime time.Time

func (jat *JiraAuditTime) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), "\"")
	if str == "" || str == "null" {
		return nil
	}

	// JIRA audit format: 2026-01-06T16:11:45.660+0000
	// Convert to RFC3339 format: 2026-01-06T16:11:45.660+00:00
	if len(str) >= 5 && str[len(str)-5] == '+' {
		str = str[:len(str)-2] + ":" + str[len(str)-2:]
	}

	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err
	}
	*jat = JiraAuditTime(t)
	return nil
}

func (jat JiraAuditTime) MarshalJSON() ([]byte, error) {
	if time.Time(jat).IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(time.Time(jat).Format(time.RFC3339))
}

// ToTime converts JiraAuditTime back to time.Time
func (jat JiraAuditTime) ToTime() time.Time {
	return time.Time(jat)
}

type JiraData struct {
	Projects                          []JiraProject                          `json:"projects"`
	Issues                            []JiraIssue                            `json:"issues"`
	Workflows                         []JiraWorkflow                         `json:"workflows"`
	WorkflowSchemes                   []JiraWorkflowScheme                   `json:"workflow_schemes"`
	WorkflowSchemeProjectAssociations []JiraWorkflowSchemeProjectAssociation `json:"workflow_scheme_project_associations"`
	IssueTypes                        []JiraIssueType                        `json:"issue_types"`
	Fields                            []JiraField                            `json:"fields"`
	AuditRecords                      []JiraAuditRecord                      `json:"audit_records"`
	GlobalPermissions                 []JiraPermission                       `json:"global_permissions"`
	Statuses                          []JiraStatus                           `json:"statuses"`
}

type JiraProject struct {
	ID              string               `json:"id"`
	Key             string               `json:"key"`
	Name            string               `json:"name"`
	Self            string               `json:"self,omitempty"`
	Description     string               `json:"description,omitempty"`
	AvatarUrls      map[string]string    `json:"avatarUrls,omitempty"`
	ProjectCategory *JiraProjectCategory `json:"projectCategory,omitempty"`
	Insight         *JiraProjectInsight  `json:"insight,omitempty"`
	Simplified      bool                 `json:"simplified,omitempty"`
	Style           string               `json:"style,omitempty"`
	Lead            *JiraUser            `json:"lead,omitempty"`
	Components      []JiraComponent      `json:"components,omitempty"`
	IssueTypes      []JiraIssueType      `json:"issueTypes,omitempty"`
}

type JiraProjectCategory struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Self        string `json:"self,omitempty"`
}

type JiraComponent struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Self         string    `json:"self,omitempty"`
	Assignee     *JiraUser `json:"assignee,omitempty"`
	AssigneeType string    `json:"assigneeType,omitempty"`
	Project      string    `json:"project,omitempty"`
	ProjectID    int64     `json:"projectId,omitempty"`
}

type JiraProjectInsight struct {
	LastIssueUpdateTime string `json:"lastIssueUpdateTime,omitempty"`
	TotalIssueCount     int64  `json:"totalIssueCount,omitempty"`
}

type JiraUser struct {
	AccountID   string            `json:"accountId,omitempty"`
	AccountType string            `json:"accountType,omitempty"`
	Active      bool              `json:"active,omitempty"`
	AvatarUrls  map[string]string `json:"avatarUrls,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Email       string            `json:"emailAddress,omitempty"`
	Key         string            `json:"key,omitempty"`
	Name        string            `json:"name,omitempty"`
	Self        string            `json:"self,omitempty"`
}

type JiraProjectSearchResponse struct {
	IsLast     bool          `json:"isLast"`
	MaxResults int           `json:"maxResults"`
	NextPage   string        `json:"nextPage,omitempty"`
	Self       string        `json:"self"`
	StartAt    int           `json:"startAt"`
	Total      int           `json:"total"`
	Values     []JiraProject `json:"values"`
}

type JiraWorkflow struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	Scope            JiraScope                `json:"scope"`
	IsEditable       bool                     `json:"isEditable,omitempty"`
	StartPointLayout JiraLayout               `json:"startPointLayout,omitempty"`
	Statuses         []JiraWorkflowStatus     `json:"statuses,omitempty"`
	Transitions      []JiraWorkflowTransition `json:"transitions,omitempty"`
	Version          JiraWorkflowVersion      `json:"version,omitempty"`
	// Additional fields from official API - use strings for timestamps
	Created       string `json:"created,omitempty"`
	Modified      string `json:"modified,omitempty"`
	DefaultStatus string `json:"defaultStatus,omitempty"`
	Published     bool   `json:"published,omitempty"`
	WorkflowOwner string `json:"workflowOwner,omitempty"`
}

type JiraWorkflowSearchResponse struct {
	IsLast     bool           `json:"isLast"`
	MaxResults int            `json:"maxResults"`
	NextPage   string         `json:"nextPage,omitempty"`
	Self       string         `json:"self"`
	StartAt    int            `json:"startAt"`
	Total      int            `json:"total"`
	Values     []JiraWorkflow `json:"values"`
	Statuses   []JiraStatus   `json:"statuses,omitempty"`
}

type JiraScope struct {
	Type    string       `json:"type"`
	Project *JiraProject `json:"project,omitempty"`
}

type JiraLayout struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type JiraWorkflowStatus struct {
	ID                    string                     `json:"id"`
	Name                  string                     `json:"name"`
	Description           string                     `json:"description,omitempty"`
	Scope                 JiraScope                  `json:"scope"`
	StatusCategory        string                     `json:"statusCategory,omitempty"`
	StatusReference       string                     `json:"statusReference"`
	Deprecated            bool                       `json:"deprecated,omitempty"`
	Layout                JiraLayout                 `json:"layout,omitempty"`
	Properties            map[string]interface{}     `json:"properties,omitempty"`
	ApprovalConfiguration *JiraApprovalConfiguration `json:"approvalConfiguration,omitempty"`
}

type JiraApprovalConfiguration struct {
	Approvals []JiraApprovalStatus `json:"approvals,omitempty"`
}

type JiraApprovalStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type JiraWorkflowTransition struct {
	ID                string                  `json:"id"`
	Name              string                  `json:"name"`
	Description       string                  `json:"description,omitempty"`
	ToStatusReference string                  `json:"toStatusReference,omitempty"`
	Type              string                  `json:"type"`
	Actions           []JiraWorkflowRule      `json:"actions,omitempty"`
	Links             []JiraTransitionLink    `json:"links,omitempty"`
	Properties        map[string]interface{}  `json:"properties,omitempty"`
	Triggers          []JiraWorkflowTrigger   `json:"triggers,omitempty"`
	Validators        []JiraWorkflowValidator `json:"validators,omitempty"`
}

type JiraTransitionLink struct {
	FromPort            int    `json:"fromPort,omitempty"`
	FromStatusReference string `json:"fromStatusReference,omitempty"`
	ToPort              int    `json:"toPort,omitempty"`
}

type JiraWorkflowVersion struct {
	ID            string `json:"id"`
	VersionNumber int    `json:"versionNumber"`
}

type JiraWorkflowTimestamp struct {
	Timestamp int64  `json:"timestamp,omitempty"`
	Format    string `json:"format,omitempty"`
}

type JiraWorkflowRule struct {
	RuleKey     string                 `json:"ruleKey"`
	RuleType    string                 `json:"ruleType"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

type JiraWorkflowTrigger struct {
	RuleKey     string                 `json:"ruleKey"`
	RuleType    string                 `json:"ruleType"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Type        string                 `json:"type,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

type JiraWorkflowValidator struct {
	RuleKey      string                 `json:"ruleKey"`
	RuleType     string                 `json:"ruleType"`
	Name         string                 `json:"name,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Expression   string                 `json:"expression,omitempty"`
	ErrorMessage string                 `json:"errorMessage,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

type JiraStatus struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Scope           JiraScope `json:"scope"`
	StatusCategory  string    `json:"statusCategory,omitempty"`
	StatusReference string    `json:"statusReference,omitempty"`
	// Additional fields from API
	IconUrl string `json:"iconUrl,omitempty"`
	Self    string `json:"self,omitempty"`
}

type JiraStatusSearchResponse struct {
	IsLast     bool         `json:"isLast"`
	MaxResults int          `json:"maxResults"`
	NextPage   string       `json:"nextPage,omitempty"`
	Self       string       `json:"self"`
	StartAt    int          `json:"startAt"`
	Total      int          `json:"total"`
	Values     []JiraStatus `json:"values"`
}

type JiraWorkflowSchemeProjectAssociation struct {
	ProjectIds     []string           `json:"projectIds"`
	WorkflowScheme JiraWorkflowScheme `json:"workflowScheme"`
}

type JiraWorkflowSchemeProjectAssociationsResponse struct {
	Values []JiraWorkflowSchemeProjectAssociation `json:"values"`
}

// JiraTransition kept for backward compatibility
type JiraTransition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	To   string `json:"to,omitempty"`
}

type JiraWorkflowSchemeSearchResponse struct {
	IsLast     bool                 `json:"isLast"`
	MaxResults int                  `json:"maxResults"`
	NextPage   string               `json:"nextPage,omitempty"`
	Self       string               `json:"self"`
	StartAt    int                  `json:"startAt"`
	Total      int                  `json:"total"`
	Values     []JiraWorkflowScheme `json:"values"`
}

type JiraWorkflowScheme struct {
	ID                int64             `json:"id"`
	Name              string            `json:"name"`
	Description       string            `json:"description,omitempty"`
	DefaultWorkflow   string            `json:"defaultWorkflow,omitempty"`
	IssueTypeMappings map[string]string `json:"issueTypeMappings,omitempty"`
	Draft             bool              `json:"draft,omitempty"`
	Self              string            `json:"self,omitempty"`
}

type JiraIssueType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraField struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Schema JiraSchema `json:"schema,omitempty"`
}

type JiraSchema struct {
	Type     string `json:"type,omitempty"`
	System   string `json:"system,omitempty"`
	Items    string `json:"items,omitempty"`
	Custom   string `json:"custom,omitempty"`
	CustomID int64  `json:"customId,omitempty"`
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
	ID              int64                     `json:"id"`
	Summary         string                    `json:"summary"`
	Created         JiraAuditTime             `json:"created"`
	AuthorAccountId string                    `json:"authorAccountId,omitempty"`
	AuthorKey       string                    `json:"authorKey,omitempty"`
	Category        string                    `json:"category"`
	Description     string                    `json:"description,omitempty"`
	EventSource     string                    `json:"eventSource,omitempty"`
	RemoteAddress   string                    `json:"remoteAddress,omitempty"`
	AssociatedItems []JiraAuditAssociatedItem `json:"associatedItems,omitempty"`
	ChangedValues   []JiraAuditChangedValue   `json:"changedValues,omitempty"`
	ObjectItem      *JiraAuditObjectItem      `json:"objectItem,omitempty"`
}

type JiraAuditAssociatedItem struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	ParentID   string `json:"parentId,omitempty"`
	ParentName string `json:"parentName,omitempty"`
	TypeName   string `json:"typeName,omitempty"`
}

type JiraAuditChangedValue struct {
	ChangedFrom string `json:"changedFrom,omitempty"`
	ChangedTo   string `json:"changedTo,omitempty"`
	FieldName   string `json:"fieldName,omitempty"`
}

type JiraAuditObjectItem struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	ParentID   string `json:"parentId,omitempty"`
	ParentName string `json:"parentName,omitempty"`
	TypeName   string `json:"typeName,omitempty"`
}

type JiraPermission struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

type JiraPermissionsResponse struct {
	Permissions map[string]JiraPermission `json:"permissions"`
}

type JiraPermissionScheme struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
