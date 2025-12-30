# Jira Compliance Plugin Plan

This plugin for the `compliance-framework` evaluates Jira/JSM data to ensure Change Request processes are followed correctly before deployments.

## Architecture

The plugin implements the `Runner` interface from the `compliance-framework/agent`. It collects data from multiple Jira APIs and evaluates policies to generate compliance evidence.

## Goals

*   **Authentication**: Support Service Account + OAuth2 (2LO) and API Tokens.
*   **Data Collection**:
    *   **Jira Platform**: Projects, Workflows, Schemes, Issues, Fields, Audit Records, Permissions, Remote Links.
    *   **JSM**: Service Desks, Request Types, Approvals, SLAs.
    *   **Jira Software**: Dev Info (PRs/commits), Deployment info.
*   **Compliance Checks**:
    *   Approval gate presence in workflows.
    *   GitHub link binding for projects.
    *   Minimal approvals verification.
    *   Deployment date vs. Approval date correctness.
    *   Detection of bypasses or compliance drift.

## Implementation Roadmap

### Phase 1: Foundation
- [x] Initialize repository and update `go.mod` (module name: `github.com/compliance-framework/plugin-jira`).
- [x] Define `PluginConfig` structure for Jira-specific settings (URL, Auth, Project filters).
- [x] Implement `Configure` method to handle plugin setup.

### Phase 2: Jira Client & Authentication
- [x] Implement Jira client wrapper supporting Cloud (/v3) and DC (/v2) endpoints.
- [x] Add OAuth2 (2LO) client credentials flow.
- [x] Add API Token / Basic Auth fallback.

### Phase 3: Data Collection (Collectors)
- [x] **Platform Collector**:
    *   `GetProjects()`: List and metadata.
    *   `GetWorkflows()`: Workflow steps and transitions.
    *   `GetWorkflowSchemes()`: Project-workflow mapping.
    *   `SearchIssues(jql)`: Find Change Requests.
    *   `GetChangelog(issueId)`: History of transitions and approvals.
- [x] **JSM Collector**:
    *   `GetApprovals(issueId)`: Extraction of JSM-native approvals.
    *   `GetSLAs(issueId)`: Timing signals for approvals.
- [x] **Software Collector**:
    *   `GetDevInfo(issueId)`: Linked PRs and commits.
    *   `GetDeployments(issueId)`: Deployment records.

### Phase 4: Policy Evaluation & Evidence
- [x] Map Jira data to `TrackedJiraData` structure for policy evaluation.
- [x] Implement `EvaluatePolicies` logic using `policyManager`.
- [ ] Generate OPA-compatible inputs from collected Jira metadata.
- [ ] Define standard evidence structure for Change Request compliance.

### Phase 5: Refinement & Testing
- [ ] Add comprehensive logging.
- [ ] Implement unit tests for data extraction logic.
- [x] Document configuration parameters in `README.md`.

## Configuration Schema

```go
type PluginConfig struct {
    BaseURL           string `mapstructure:"base_url"`
    AuthType          string `mapstructure:"auth_type"` // "oauth2" or "token"
    ClientID          string `mapstructure:"client_id"`
    ClientSecret      string `mapstructure:"client_secret"`
    APIToken          string `mapstructure:"api_token"`
    UserEmail         string `mapstructure:"user_email"`
    ProjectKeys       []string `mapstructure:"project_keys"`
    ExcludedWorkflows []string `mapstructure:"excluded_workflows"`
    PolicyLabels      string `mapstructure:"policy_labels"`
}
```
