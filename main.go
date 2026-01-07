package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-jira/internal/jira"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

type Validator interface {
	Validate() error
}

type PluginConfig struct {
	BaseURL      string `mapstructure:"base_url"`
	AuthType     string `mapstructure:"auth_type"` // "oauth2" or "token"
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	APIToken     string `mapstructure:"api_token"`
	UserEmail    string `mapstructure:"user_email"`
	ProjectKeys  string `mapstructure:"project_keys"` // Comma-separated list

	// Hack to configure policy labels and generate correct evidence UUIDs
	PolicyLabels string `mapstructure:"policy_labels"`
}

// ParsedConfig holds the parsed and processed configuration
type ParsedConfig struct {
	BaseURL      string            `mapstructure:"base_url"`
	AuthType     string            `mapstructure:"auth_type"`
	ClientID     string            `mapstructure:"client_id"`
	ClientSecret string            `mapstructure:"client_secret"`
	APIToken     string            `mapstructure:"api_token"`
	UserEmail    string            `mapstructure:"user_email"`
	ProjectKeys  []string          `mapstructure:"project_keys"`
	PolicyLabels map[string]string `mapstructure:"policy_labels"`
}

func (c *PluginConfig) Parse() (*ParsedConfig, error) {
	policyLabels := map[string]string{}
	if c.PolicyLabels != "" {
		if err := json.Unmarshal([]byte(c.PolicyLabels), &policyLabels); err != nil {
			return nil, fmt.Errorf("could not parse policy labels: %w", err)
		}
	}

	parsed := &ParsedConfig{
		BaseURL:      c.BaseURL,
		AuthType:     c.AuthType,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		APIToken:     c.APIToken,
		UserEmail:    c.UserEmail,
		PolicyLabels: policyLabels,
	}

	if c.ProjectKeys != "" {
		parts := strings.Split(c.ProjectKeys, ",")
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				parsed.ProjectKeys = append(parsed.ProjectKeys, s)
			}
		}
	}

	return parsed, nil
}

func (c *PluginConfig) Validate() error {
	if c.BaseURL == "" {
		return errors.New("base_url is required")
	}
	if c.AuthType != "oauth2" && c.AuthType != "token" {
		return errors.New("auth_type must be either 'oauth2' or 'token'")
	}
	if c.AuthType == "oauth2" {
		if c.ClientID == "" || c.ClientSecret == "" {
			return errors.New("client_id and client_secret are required for oauth2")
		}
	}
	if c.AuthType == "token" {
		if c.APIToken == "" || c.UserEmail == "" {
			return errors.New("api_token and user_email are required for token auth")
		}
	}
	return nil
}

// TrackedFileInfo holds information about a tracked file and its attestation
type JiraPlugin struct {
	Logger hclog.Logger

	config       *PluginConfig
	parsedConfig *ParsedConfig
	client       *http.Client
}

func (l *JiraPlugin) initClient(ctx context.Context) error {
	if l.parsedConfig.AuthType == "oauth2" {
		l.Logger.Debug("Initializing Jira client with OAuth2")
		l.client = jira.NewOAuth2Client(l.parsedConfig.ClientID, l.parsedConfig.ClientSecret, l.parsedConfig.BaseURL, l.Logger)
	} else {
		l.Logger.Debug("Initializing Jira client with Token")
		// Token auth
		l.client = jira.NewTokenAuthClient(l.parsedConfig.UserEmail, l.parsedConfig.APIToken)
	}
	return nil
}

func (l *JiraPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.Logger.Info("Configuring Jira Plugin")
	config := &PluginConfig{}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}
	l.Logger.Debug("configuration decoded", "config", config)

	if err := config.Validate(); err != nil {
		l.Logger.Error("Error validating config", "error", err)
		return nil, err
	}

	l.config = config
	// Parse JSON-encoded configuration fields
	parsed, err := config.Parse()
	if err != nil {
		l.Logger.Error("Error parsing config", "error", err)
		return nil, err
	}
	l.parsedConfig = parsed

	return &proto.ConfigureResponse{}, nil
}

func (l *JiraPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	if err := l.initClient(ctx); err != nil {
		l.Logger.Error("Error initializing Jira client", "error", err)
		return nil, err
	}

	client, err := jira.NewClient(l.parsedConfig.BaseURL, l.client, l.Logger)
	if err != nil {
		l.Logger.Error("Error creating JIRA client", "error", err)
		return nil, err
	}

	jiraData, err := l.collectData(ctx, client)
	indentedJSON, _ := json.MarshalIndent(jiraData, "", "  ")
	os.WriteFile("/data/jira_data.json", indentedJSON, 0o644)
	if err != nil {
		l.Logger.Error("Error collecting Jira data", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	evidences, err := l.EvaluatePolicies(ctx, jiraData, req)
	if err != nil {
		l.Logger.Error("Error evaluating policies", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	l.Logger.Debug("calculated evidences", "evidences", evidences)
	if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.Logger.Error("Error creating evidence", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

func (l *JiraPlugin) collectData(ctx context.Context, client *jira.Client) (*jira.JiraData, error) {
	data := &jira.JiraData{}

	// 1. Fetch Global Metadata
	var err error
	data.Workflows, err = client.FetchWorkflows(ctx)
	if err != nil {
		l.Logger.Warn("failed to fetch workflows", "error", err)
	}

	data.WorkflowSchemes, err = client.FetchWorkflowSchemes(ctx)
	if err != nil {
		l.Logger.Warn("failed to fetch workflow schemes", "error", err)
	}

	data.IssueTypes, err = client.FetchIssueTypes(ctx)
	if err != nil {
		l.Logger.Warn("failed to fetch issue types", "error", err)
	}

	data.Fields, err = client.FetchFields(ctx)
	if err != nil {
		l.Logger.Warn("failed to fetch fields", "error", err)
	}

	data.AuditRecords, err = client.FetchAuditRecords(ctx)
	if err != nil {
		l.Logger.Warn("failed to fetch audit records", "error", err)
	}

	data.GlobalPermissions, err = client.FetchGlobalPermissions(ctx)
	if err != nil {
		l.Logger.Warn("failed to fetch global permissions", "error", err)
	}

	// 2. Fetch Projects
	projects, err := client.FetchProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch projects: %w", err)
	}

	// Filter by project keys if configured
	if len(l.parsedConfig.ProjectKeys) > 0 {
		filtered := []jira.JiraProject{}
		for _, p := range projects {
			for _, key := range l.parsedConfig.ProjectKeys {
				if p.Key == key {
					filtered = append(filtered, p)
					break
				}
			}
		}
		data.Projects = filtered
	} else {
		data.Projects = projects
	}

	// 3. Projects are already fetched with all available details
	l.Logger.Debug("Project details fetched", "count", len(data.Projects))

	// 4. Search for Change Request issues
	issues, err := client.SearchChangeRequests(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to search issues: %w", err)
	}
	data.Issues = issues
	// 5. Fetch Details, Changelog, Approvals, SLAs, DevInfo, and Deployments for each issue
	for i, issue := range data.Issues {
		l.Logger.Info("Fetching details for issue", "issue", issue.Key)
		changelog, err := client.FetchIssueChangelog(ctx, issue.Key)
		if err != nil {
			l.Logger.Warn("failed to fetch changelog for issue", "issue", issue.Key, "error", err)
		} else {
			data.Issues[i].Changelog = changelog
		}

		approvals, err := client.FetchIssueApprovals(ctx, issue.Key)
		if err != nil {
			l.Logger.Warn("failed to fetch approvals for issue", "issue", issue.Key, "error", err)
		} else {
			data.Issues[i].Approvals = approvals
		}

		slas, err := client.FetchIssueSLAs(ctx, issue.Key)
		if err != nil {
			l.Logger.Warn("failed to fetch SLAs for issue", "issue", issue.Key, "error", err)
		} else {
			data.Issues[i].SLAs = slas
		}

		devInfo, err := client.FetchIssueDevInfo(ctx, issue.Key)
		if err != nil {
			l.Logger.Warn("failed to fetch dev info for issue", "issue", issue.Key, "error", err)
		} else {
			data.Issues[i].DevInfo = devInfo
		}

		deployments, err := client.FetchIssueDeployments(ctx, issue.Key)
		if err != nil {
			l.Logger.Warn("failed to fetch deployments for issue", "issue", issue.Key, "error", err)
		} else {
			data.Issues[i].Deployments = deployments
		}
	}
	return data, nil
}

func (l *JiraPlugin) EvaluatePolicies(ctx context.Context, data *jira.JiraData, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)
	activities = append(activities, &proto.Activity{
		Title: "Collect Jira Compliance Data",
		Steps: []*proto.Step{
			{
				Title:       "Authenticate with Jira",
				Description: "Authenticate with Jira Platform and Service Management APIs.",
			},
			{
				Title:       "Fetch Jira Projects and Workflows",
				Description: "Retrieve project metadata, workflow configurations, and issue types.",
			},
			{
				Title:       "Search and Analyze Change Requests",
				Description: "Search for Change Request issues and analyze their transitions, approvals, and linked development data.",
			},
		},
	})

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Jira Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-jira",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework Jira Plugin"),
				},
			},
			Props: nil,
		},
	}

	components := []*proto.Component{
		{
			Identifier:  "jira-platform",
			Type:        "service",
			Title:       "Jira Platform",
			Description: "Atlassian Jira Platform providing project and workflow management.",
			Purpose:     "To serve as the system of record for change management and workflows.",
			Links: []*proto.Link{
				{
					Href: l.config.BaseURL,
					Rel:  policyManager.Pointer("component"),
					Text: policyManager.Pointer("Jira Instance"),
				},
			},
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: "jira-data-collection",
			Type:       "jira-compliance-data",
			Title:      "Jira Compliance Data",
			Props:      []*proto.Property{},
			Links: []*proto.Link{
				{
					Href: l.config.BaseURL,
					Text: policyManager.Pointer("Jira Base URL"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "jira-platform",
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "jira-platform",
		},
	}

	labels := map[string]string{}
	maps.Copy(labels, l.parsedConfig.PolicyLabels)
	labels["provider"] = "jira"

	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			l.Logger,
			labels,
			subjects,
			components,
			inventory,
			actors,
			activities,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	return evidences, accumulatedErrors
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		JSONFormat: true,
	})

	jiraPlugin := &JiraPlugin{
		Logger: logger,
	}

	logger.Info("Starting Jira Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: jiraPlugin,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
