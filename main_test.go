package main

import (
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConfigureStoresPolicyData(t *testing.T) {
	policyData, err := structpb.NewStruct(map[string]interface{}{
		"required_approvers": []interface{}{"change-board"},
	})
	if err != nil {
		t.Fatalf("build policy data: %v", err)
	}

	plugin := &JiraPlugin{Logger: hclog.NewNullLogger()}
	config := map[string]string{
		"base_url":   "https://example.atlassian.net",
		"auth_type":  "token",
		"api_token":  "test-token",
		"user_email": "bot@example.com",
	}

	if _, err := plugin.Configure(&proto.ConfigureRequest{Config: config, PolicyData: policyData}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	approvers, ok := plugin.policyData["required_approvers"].([]interface{})
	if !ok || len(approvers) != 1 || approvers[0] != "change-board" {
		t.Fatalf("unexpected policy data: %#v", plugin.policyData)
	}

	if _, err := plugin.Configure(&proto.ConfigureRequest{Config: config}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if plugin.policyData != nil {
		t.Fatalf("expected policy data to be cleared, got %#v", plugin.policyData)
	}
}
