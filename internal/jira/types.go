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

// JiraChangelogTime handles the timestamp format used in JIRA changelog entries
type JiraChangelogTime time.Time

func (jct *JiraChangelogTime) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), "\"")
	if str == "" || str == "null" {
		return nil
	}

	// JIRA changelog format: 2026-01-07T14:29:44.470+0100
	// Convert to RFC3339 format: 2026-01-07T14:29:44.470+01:00
	if len(str) >= 5 && (str[len(str)-5] == '+' || str[len(str)-5] == '-') {
		str = str[:len(str)-2] + ":" + str[len(str)-2:]
	}

	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err
	}
	*jct = JiraChangelogTime(t)
	return nil
}

func (jct JiraChangelogTime) MarshalJSON() ([]byte, error) {
	if time.Time(jct).IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(time.Time(jct).Format(time.RFC3339))
}

// ToTime converts JiraChangelogTime back to time.Time
func (jct JiraChangelogTime) ToTime() time.Time {
	return time.Time(jct)
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
	WorkflowCapabilities              *JiraWorkflowCapabilities              `json:"workflow_capabilities,omitempty"`
}

// ProjectCentricData organizes all Jira information by projects
type ProjectCentricData struct {
	Projects          []ProjectData     `json:"projects"`
	GlobalPermissions []JiraPermission  `json:"global_permissions,omitempty"`
	AuditRecords      []JiraAuditRecord `json:"audit_records,omitempty"`
}

// ProjectData contains all information related to a specific project
type ProjectData struct {
	Project         JiraProject          `json:"project"`
	WorkflowSchemes []JiraWorkflowScheme `json:"workflow_schemes,omitempty"`
	Workflows       []JiraWorkflow       `json:"workflows,omitempty"`
	Issues          []ProjectIssue       `json:"issues,omitempty"`
	IssueTypes      []JiraIssueType      `json:"issue_types,omitempty"`
	Fields          []JiraField          `json:"fields,omitempty"`
	Statuses        []JiraStatus         `json:"statuses,omitempty"`
}

// ProjectIssue represents an issue within a project context
type ProjectIssue struct {
	JiraIssue
	Approvals   []JiraApproval   `json:"approvals,omitempty"`
	SLAs        []JiraSLA        `json:"slas,omitempty"`
	DevInfo     *JiraDevInfo     `json:"dev_info,omitempty"`
	Deployments []JiraDeployment `json:"deployments,omitempty"`
}

// isOpenIssue determines if an issue is still open based on its status category
func isOpenIssue(issue JiraIssue) bool {
	// Access status through the Fields map
	statusField, exists := issue.Fields["status"]
	if !exists {
		// Default to including issues without status
		return true
	}

	// Type assert to map[string]interface{}
	statusMap, ok := statusField.(map[string]interface{})
	if !ok {
		// Default to including issues with malformed status
		return true
	}

	// Access status category
	statusCategoryField, exists := statusMap["statusCategory"]
	if !exists {
		// Default to including issues without status category
		return true
	}

	// Type assert to map[string]interface{}
	statusCategoryMap, ok := statusCategoryField.(map[string]interface{})
	if !ok {
		// Default to including issues with malformed status category
		return true
	}

	// Get status category name
	categoryNameField, exists := statusCategoryMap["name"]
	if !exists {
		// Default to including issues without category name
		return true
	}

	categoryName, ok := categoryNameField.(string)
	if !ok {
		// Default to including issues with non-string category name
		return true
	}

	switch categoryName {
	case "To Do", "In Progress":
		return true
	case "Done":
		return false
	default:
		// Default to including unknown categories as "open" for safety
		return true
	}
}

// ToProjectCentric converts JiraData to ProjectCentricData by organizing all information by projects
func (jd *JiraData) ToProjectCentric() *ProjectCentricData {
	result := &ProjectCentricData{
		Projects:          make([]ProjectData, 0),
		GlobalPermissions: jd.GlobalPermissions,
		AuditRecords:      jd.AuditRecords,
	}

	// Create maps for efficient lookups
	workflowSchemeMap := make(map[int64]JiraWorkflowScheme)
	for _, ws := range jd.WorkflowSchemes {
		workflowSchemeMap[ws.ID] = ws
	}

	workflowMap := make(map[string]JiraWorkflow)
	for _, w := range jd.Workflows {
		workflowMap[w.Name] = w
	}

	issueTypeMap := make(map[string]JiraIssueType)
	for _, it := range jd.IssueTypes {
		issueTypeMap[it.Name] = it
	}

	fieldMap := make(map[string]JiraField)
	for _, f := range jd.Fields {
		fieldMap[f.ID] = f
	}

	statusMap := make(map[string]JiraStatus)
	for _, s := range jd.Statuses {
		statusMap[s.Name] = s
	}

	// Group issues by project
	issuesByProject := make(map[string][]JiraIssue)
	for _, issue := range jd.Issues {
		if issue.Fields != nil {
			if projectObj, exists := issue.Fields["project"]; exists {
				if projectMap, ok := projectObj.(map[string]interface{}); ok {
					if id, exists := projectMap["id"]; exists {
						if projectId, ok := id.(string); ok {
							issuesByProject[projectId] = append(issuesByProject[projectId], issue)
						}
					}
				}
			}
		}
	}

	// Process each project
	for _, project := range jd.Projects {
		projectData := ProjectData{
			Project: project,
		}

		// Find workflow schemes for this project
		projectSchemeIDs := make(map[int64]bool)
		for _, assoc := range jd.WorkflowSchemeProjectAssociations {
			for _, projectID := range assoc.ProjectIds {
				if projectID == project.ID {
					projectSchemeIDs[assoc.WorkflowScheme.ID] = true
					break
				}
			}
		}

		// Add workflow schemes for this project
		for schemeID := range projectSchemeIDs {
			if scheme, exists := workflowSchemeMap[schemeID]; exists {
				projectData.WorkflowSchemes = append(projectData.WorkflowSchemes, scheme)
			}
		}

		// Add workflows referenced by the project's workflow schemes AND used by project's issue types
		projectWorkflowNames := make(map[string]bool)
		projectIssueTypeNames := make(map[string]bool)

		// First, collect all issue types used by this project's issues
		if projectIssues, exists := issuesByProject[project.ID]; exists {
			for _, issue := range projectIssues {
				if issue.Fields != nil {
					if issueTypeObj, exists := issue.Fields["issuetype"]; exists {
						if issueTypeMap, ok := issueTypeObj.(map[string]interface{}); ok {
							if name, exists := issueTypeMap["name"]; exists {
								if issueTypeName, ok := name.(string); ok {
									projectIssueTypeNames[issueTypeName] = true
								}
							}
						}
					}
				}
			}
		}

		// Then, collect workflows from workflow schemes that are mapped to the used issue types
		for _, scheme := range projectData.WorkflowSchemes {
			// Check default workflow if it's mapped to a used issue type
			if scheme.DefaultWorkflow != "" {
				// Check if any issue type mapping uses this workflow
				for issueTypeName := range projectIssueTypeNames {
					if mapping, exists := scheme.IssueTypeMappings[issueTypeName]; exists && mapping == scheme.DefaultWorkflow {
						projectWorkflowNames[scheme.DefaultWorkflow] = true
						break
					}
				}
			}

			// Check issue type mappings for workflows used by our issue types
			for issueTypeName, workflowName := range scheme.IssueTypeMappings {
				if _, issueTypeUsed := projectIssueTypeNames[issueTypeName]; issueTypeUsed {
					projectWorkflowNames[workflowName] = true
				}
			}
		}

		// Fallback: If no workflow schemes found, try to include workflows that might be related to this project
		// This handles cases where associations are missing or projects use different workflow management
		if len(projectWorkflowNames) == 0 {
			// Try to match workflows by project ID in workflow name or scope
			for _, workflow := range jd.Workflows {
				// Check if workflow name contains project ID or key
				if strings.Contains(workflow.Name, project.ID) || strings.Contains(workflow.Name, project.Key) {
					projectWorkflowNames[workflow.Name] = true
				}
				// For next-gen projects, check if workflow scope matches project
				if workflow.Scope.Type == "PROJECT" && workflow.Scope.Project.ID == project.ID {
					projectWorkflowNames[workflow.Name] = true
				}
			}
		}

		for workflowName := range projectWorkflowNames {
			if workflow, exists := workflowMap[workflowName]; exists {
				// Create a copy of the workflow to avoid modifying the original
				workflowCopy := workflow

				// Merge approval configurations from global workflow statuses
				if len(workflowCopy.Statuses) > 0 {
					// Find the corresponding global workflow to get approval configurations
					for _, globalWorkflow := range jd.Workflows {
						if globalWorkflow.Name == workflow.Name {
							// Create a map of statusReference to approval configuration
							globalApprovalConfigs := make(map[string]*JiraApprovalConfiguration)
							for _, globalStatus := range globalWorkflow.Statuses {
								if globalStatus.ApprovalConfiguration != nil {
									globalApprovalConfigs[globalStatus.StatusReference] = globalStatus.ApprovalConfiguration
								}
							}

							// Apply approval configurations to project workflow statuses
							for i, projectStatus := range workflowCopy.Statuses {
								if approvalConfig, exists := globalApprovalConfigs[projectStatus.StatusReference]; exists {
									workflowCopy.Statuses[i].ApprovalConfiguration = approvalConfig
								}
							}
							break
						}
					}

					// Enrich workflow statuses with global status details using statusReference
					// Create a map of status ID to full status details from global statuses
					globalStatusMap := make(map[string]*JiraStatus)
					for _, globalStatus := range jd.Statuses {
						globalStatusMap[globalStatus.ID] = &globalStatus
					}

					// Apply global status details to workflow statuses
					for i, projectStatus := range workflowCopy.Statuses {
						if projectStatus.StatusReference != "" {
							if globalStatus, exists := globalStatusMap[projectStatus.StatusReference]; exists {
								// Only fill in missing fields from global status
								if projectStatus.ID == "" {
									workflowCopy.Statuses[i].ID = globalStatus.ID
								}
								if projectStatus.Name == "" {
									workflowCopy.Statuses[i].Name = globalStatus.Name
								}
								if projectStatus.Description == "" && globalStatus.Description != "" {
									workflowCopy.Statuses[i].Description = globalStatus.Description
								}
								if projectStatus.StatusCategory == "" && globalStatus.StatusCategory != "" {
									workflowCopy.Statuses[i].StatusCategory = globalStatus.StatusCategory
								}
							}
						}
					}
				}

				projectData.Workflows = append(projectData.Workflows, workflowCopy)
			}
		}

		// Add issues for this project (only open issues)
		if projectIssues, exists := issuesByProject[project.ID]; exists {
			for _, issue := range projectIssues {
				// Only include open issues
				if !isOpenIssue(issue) {
					continue
				}

				projectIssue := ProjectIssue{
					JiraIssue: issue,
					// Copy the service desk fetched data
					Approvals:   issue.Approvals,
					SLAs:        issue.SLAs,
					DevInfo:     issue.DevInfo,
					Deployments: issue.Deployments,
				}
				projectData.Issues = append(projectData.Issues, projectIssue)
			}
		}

		for issueTypeName := range projectIssueTypeNames {
			if issueType, exists := issueTypeMap[issueTypeName]; exists {
				projectData.IssueTypes = append(projectData.IssueTypes, issueType)
			}
		}

		// Add fields used by this project's issues
		projectFieldIDs := make(map[string]bool)
		for _, issue := range projectData.Issues {
			if issue.Fields != nil {
				for fieldName := range issue.Fields {
					// Try to find field by name (this is a simplified approach)
					// In practice, you might need a more sophisticated mapping
					for _, field := range jd.Fields {
						if field.Name == fieldName {
							projectFieldIDs[field.ID] = true
							break
						}
					}
				}
			}
		}

		for fieldID := range projectFieldIDs {
			if field, exists := fieldMap[fieldID]; exists {
				projectData.Fields = append(projectData.Fields, field)
			}
		}

		// Add statuses used by this project's issues
		projectStatusNames := make(map[string]bool)
		for _, issue := range projectData.Issues {
			if issue.Fields != nil {
				if statusObj, exists := issue.Fields["status"]; exists {
					if statusMap, ok := statusObj.(map[string]interface{}); ok {
						if name, exists := statusMap["name"]; exists {
							if statusName, ok := name.(string); ok {
								projectStatusNames[statusName] = true
							}
						}
					}
				}
			}
		}

		for statusName := range projectStatusNames {
			if status, exists := statusMap[statusName]; exists {
				projectData.Statuses = append(projectData.Statuses, status)
			}
		}

		result.Projects = append(result.Projects, projectData)
	}

	return result
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
	Active              string   `json:"active"`                        // Whether the approval configuration is active
	ConditionType       string   `json:"conditionType"`                 // "number", "percent", "numberPerPrincipal"
	ConditionValue      string   `json:"conditionValue"`                // Number or percentage of approvals required
	Exclude             []string `json:"exclude,omitempty"`             // Roles to exclude as possible approvers
	FieldID             string   `json:"fieldId"`                       // Custom field ID of "Approvers" or "Approver Groups" field
	PrePopulatedFieldID *string  `json:"prePopulatedFieldId,omitempty"` // Field used to pre-populate Approver field
	TransitionApproved  string   `json:"transitionApproved"`            // Transition ID for approved state
	TransitionRejected  string   `json:"transitionRejected"`            // Transition ID for rejected state
}

type JiraApprovalStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type JiraWorkflowTransition struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description,omitempty"`
	ToStatusReference string                 `json:"toStatusReference,omitempty"`
	FromStatus        []string               `json:"fromStatus,omitempty"`
	Screen            *JiraWorkflowScreen    `json:"screen,omitempty"`
	Properties        map[string]interface{} `json:"properties,omitempty"`
	Type              string                 `json:"type,omitempty"`
	IsInitial         bool                   `json:"isInitial,omitempty"`
	IsLooped          bool                   `json:"isLooped,omitempty"`
	IsConditional     bool                   `json:"isConditional,omitempty"`
}

type JiraWorkflowScreen struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type JiraWorkflowCapabilities struct {
	ApprovalsEnabled     bool `json:"approvalsEnabled"`     // Whether approvals are enabled for workflows
	ConditionsEnabled    bool `json:"conditionsEnabled"`    // Whether conditions are enabled for workflows
	ValidatorsEnabled    bool `json:"validatorsEnabled"`    // Whether validators are enabled for workflows
	PostFunctionsEnabled bool `json:"postFunctionsEnabled"` // Whether post functions are enabled for workflows
	RulesEnabled         bool `json:"rulesEnabled"`         // Whether rules are enabled for workflows
	ScreensEnabled       bool `json:"screensEnabled"`       // Whether screens are enabled for workflows
	PropertiesEnabled    bool `json:"propertiesEnabled"`    // Whether properties are enabled for workflows
	TransitionsEnabled   bool `json:"transitionsEnabled"`   // Whether transitions are enabled for workflows
	StatusesEnabled      bool `json:"statusesEnabled"`      // Whether statuses are enabled for workflows
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
	Changelog   *JiraChangelog         `json:"changelog"`
	Approvals   []JiraApproval         `json:"approvals"`
	SLAs        []JiraSLA              `json:"slas,omitempty"`
	DevInfo     *JiraDevInfo           `json:"dev_info,omitempty"`
	Deployments []JiraDeployment       `json:"deployments,omitempty"`
}

// JiraChangelog represents the changelog object returned by Jira API
type JiraChangelog struct {
	Histories  []JiraChangelogEntry `json:"histories"`
	StartAt    int                  `json:"startAt"`
	MaxResults int                  `json:"maxResults"`
	Total      int                  `json:"total"`
}

type JiraChangelogEntry struct {
	Author  *JiraUser           `json:"author"`
	Created JiraChangelogTime   `json:"created"`
	Items   []JiraChangelogItem `json:"items"`
}

type JiraChangelogItem struct {
	Field string `json:"field"`
	From  string `json:"fromString"`
	To    string `json:"toString"`
}

type JiraApproval struct {
	ID                string                `json:"id"`
	Name              string                `json:"name,omitempty"`
	FinalDecision     string                `json:"finalDecision,omitempty"`
	CanAnswerApproval bool                  `json:"canAnswerApproval,omitempty"`
	Approvers         []JiraApproverItem    `json:"approvers"`
	CreatedDate       JiraApprovalTimestamp `json:"createdDate,omitempty"`
	CompletedDate     JiraApprovalTimestamp `json:"completedDate,omitempty"`
}

type JiraApproverItem struct {
	Approver         JiraUser `json:"approver"`
	ApproverDecision string   `json:"approverDecision,omitempty"`
}

type JiraApprovalTimestamp struct {
	EpochMillis int64  `json:"epochMillis,omitempty"`
	Friendly    string `json:"friendly,omitempty"`
	ISO8601     string `json:"iso8601,omitempty"`
	Jira        string `json:"jira,omitempty"`
}

type JiraSLA struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	CompletedCycles []JiraSLACycle `json:"completedCycles,omitempty"`
	OngoingCycle    *JiraSLACycle  `json:"ongoingCycle,omitempty"`
	State           string         `json:"state"` // "MET", "BREACHED", "IN_PROGRESS"
}

type JiraSLACycle struct {
	BreachTime     *JiraSLATime `json:"breachTime,omitempty"`
	ElapsedTime    *JiraSLATime `json:"elapsedTime,omitempty"`
	RemainingTime  *JiraSLATime `json:"remainingTime,omitempty"`
	StartTime      *JiraSLATime `json:"startTime,omitempty"`
	StopTime       *JiraSLATime `json:"stopTime,omitempty"`
	GoalDuration   *JiraSLATime `json:"goalDuration,omitempty"`
	Breached       bool         `json:"breached,omitempty"`
	WithinCalendar bool         `json:"withinCalendar,omitempty"`
}

type JiraSLATime struct {
	Friendly string `json:"friendly"`
	Millis   int64  `json:"millis"`
	Jira     string `json:"jira"`
	ISO8601  string `json:"iso8601,omitempty"`
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
