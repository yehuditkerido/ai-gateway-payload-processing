/*
Copyright 2026 The opendatahub.io Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apikey_injection

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/gateway-api-inference-extension/pkg/bbr/framework"
	"sigs.k8s.io/gateway-api-inference-extension/pkg/epp/framework/interface/plugin"

	"github.com/opendatahub-io/ai-gateway-payload-processing/pkg/plugins/apikey-injection/auth"
	"github.com/opendatahub-io/ai-gateway-payload-processing/pkg/plugins/common/state"
)

// newTestPlugin creates an apiKeyInjectionPlugin for unit tests, bypassing the
// Handle-based Factory (which requires a real manager).
func newTestPlugin(store *secretStore) *ApiKeyInjectionPlugin {
	return &ApiKeyInjectionPlugin{
		typedName: plugin.TypedName{Type: APIKeyInjectionPluginType, Name: APIKeyInjectionPluginType},
		authHeadersGenerators: map[string]auth.AuthHeadersGenerator{
<<<<<<< Updated upstream
			state.AuthTypeSimple:   &auth.SimpleAuthGenerator{},
			state.AuthTypeGCPOAuth: &auth.GCPOAuth2Generator{},
			state.AuthTypeSigV4:    &auth.SigV4AuthGenerator{},
		},
		dataEnrichers: map[string]credentialsEnricherFunc{
			state.AuthTypeSigV4: enrichBedrockCredentials,
=======
			state.AuthTypeSimple: &auth.SimpleAuthGenerator{},
>>>>>>> Stashed changes
		},
		store: store,
	}
}

<<<<<<< Updated upstream
// newBedrockRequest creates an InferenceRequest pre-populated with a model body
// field, simulating a real client request routed to Bedrock.
func newBedrockRequest() *framework.InferenceRequest {
	req := framework.NewInferenceRequest()
	req.Body["model"] = "anthropic.claude-v2"
	req.Body["prompt"] = "hello"
	return req
}

// newBedrockCycleState builds a CycleState with credential ref, aws-sigv4 auth type and the target endpoint
func newBedrockCycleState(credsNamespace, credsName string) *framework.CycleState {
	cs := newCycleState(credsNamespace, credsName, "aws-bedrock", map[string]string{
		state.ConfigKeyAuthType: state.AuthTypeSigV4,
	})
	cs.Write(state.EndpointKey, "bedrock-runtime.us-east-1.amazonaws.com")
	return cs
}

=======
>>>>>>> Stashed changes
// newCycleState builds a CycleState with credential ref, provider, and optional config.
func newCycleState(credsNamespace, credsName, providerName string, providerConfig map[string]string) *framework.CycleState {
	cs := framework.NewCycleState()
	cs.Write(state.CredsRefName, credsName)
	cs.Write(state.CredsRefNamespace, credsNamespace)
	if providerName != "" {
		cs.Write(state.ProviderKey, providerName)
	}
	if providerConfig != nil {
		cs.Write(state.ProviderConfigKey, providerConfig)
	}
	return cs
}

func TestProcessRequest(t *testing.T) {
	tests := []struct {
		name              string
		secrets           []*corev1.Secret
		request           *framework.InferenceRequest
		prepareCycleState func() *framework.CycleState
		wantHeaders       map[string]string
		errorContains     string
	}{
		{
			name:    "simple-auth with defaults (OpenAI style)",
			secrets: []*corev1.Secret{testSecret("default", "openai-key", map[string]string{"api-key": "sk-test-key"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "openai-key", "openai", map[string]string{
					"auth-type": "simple-auth",
				})
			},
			wantHeaders: map[string]string{
				"Authorization": "Bearer sk-test-key",
			},
		},
		{
			name:    "simple-auth with custom header (Anthropic style)",
			secrets: []*corev1.Secret{testSecret("default", "anthropic-key", map[string]string{"api-key": "ant-key-123"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "anthropic-key", "anthropic", map[string]string{
					"auth-type":           "simple-auth",
					"header-name":         "x-api-key",
					"header-value-prefix": "",
				})
			},
			wantHeaders: map[string]string{
				"x-api-key": "ant-key-123",
			},
		},
		{
			name:    "simple-auth with custom header (Azure style)",
			secrets: []*corev1.Secret{testSecret("default", "azure-key", map[string]string{"api-key": "azure-key-456"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "azure-key", "azure-openai", map[string]string{
					"auth-type":           "simple-auth",
					"header-name":         "api-key",
					"header-value-prefix": "",
				})
			},
			wantHeaders: map[string]string{
				"api-key": "azure-key-456",
			},
		},
		{
			name:    "defaults to simple-auth when no auth-type specified",
			secrets: []*corev1.Secret{testSecret("default", "default-key", map[string]string{"api-key": "default-value"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "default-key", "openai", nil)
			},
			wantHeaders: map[string]string{
				"Authorization": "Bearer default-value",
			},
		},
		{
			name:    "unknown auth-type — request fails",
			secrets: []*corev1.Secret{testSecret("default", "no-provider", map[string]string{"api-key": "sk-key"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "no-provider", "openai", map[string]string{
					"auth-type": "unknown-auth-type",
				})
			},
			errorContains: "unsupported auth type",
		},
		{
			name:              "internal model no provider - skip gracefully",
			secrets:           []*corev1.Secret{testSecret("default", "no-provider", map[string]string{"api-key": "sk-key"})},
			request:           framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState { return framework.NewCycleState() },
			wantHeaders:       map[string]string{},
		},
		{
			name:    "missing credentials ref results in error",
			secrets: []*corev1.Secret{testSecret("default", "no-provider", map[string]string{"api-key": "sk-key"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				cs := framework.NewCycleState()
				cs.Write(state.ProviderKey, "openai")
				return cs
			},
			errorContains: "missing credentialRef",
		},
		{
			name:    "credentials not found results in error",
			secrets: []*corev1.Secret{},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "unknown", "openai", nil)
			},
			errorContains: "credentials not found",
		},
		{
			name:    "missing api-key field in credentials results in error",
			secrets: []*corev1.Secret{testSecret("default", "wrong-fields", map[string]string{"wrong-field": "value"})},
			request: framework.NewInferenceRequest(),
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "wrong-fields", "openai", nil)
			},
			errorContains: "failed to generate auth headers",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newSecretStore()
			for _, secret := range test.secrets {
				require.NoError(t, store.addOrUpdate(secret.GetNamespace(), secret.GetName(), secret))
			}

			plugin := newTestPlugin(store)
			err := plugin.ProcessRequest(context.Background(), test.prepareCycleState(), test.request)
			if test.errorContains != "" {
				require.ErrorContains(t, err, test.errorContains)
				return
			}
			require.NoError(t, err)
			if diff := cmp.Diff(test.wantHeaders, test.request.Headers, cmpopts.SortMaps(func(a, b string) bool { return a < b }), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("headers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProcessRequest_AWSBedrock(t *testing.T) {
	tests := []struct {
		name              string
		secrets           []*corev1.Secret
		prepareCycleState func() *framework.CycleState
		wantSecurityToken string // exact value; empty means the header must be absent
		errorContains     string
	}{
		{
			name: "produces SigV4 auth headers",
			secrets: []*corev1.Secret{testSecret("default", "bedrock-creds", map[string]string{
				"aws-access-key-id":     "AKIAIOSFODNN7EXAMPLE",
				"aws-secret-access-key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			})},
			prepareCycleState: func() *framework.CycleState { return newBedrockCycleState("default", "bedrock-creds") },
		},
		{
			name: "includes security token when session token is present",
			secrets: []*corev1.Secret{testSecret("default", "bedrock-creds", map[string]string{
				"aws-access-key-id":     "AKIAIOSFODNN7EXAMPLE",
				"aws-secret-access-key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"aws-session-token":     "FwoGZXIvYXdzEBYaDH7example-session-token",
			})},
			prepareCycleState: func() *framework.CycleState { return newBedrockCycleState("default", "bedrock-creds") },
			wantSecurityToken: "FwoGZXIvYXdzEBYaDH7example-session-token",
		},
		{
			name: "missing endpoint in cycle state returns error",
			secrets: []*corev1.Secret{testSecret("default", "bedrock-creds", map[string]string{
				"aws-access-key-id":     "AKIAIOSFODNN7EXAMPLE",
				"aws-secret-access-key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			})},
			prepareCycleState: func() *framework.CycleState {
				return newCycleState("default", "bedrock-creds", "aws-bedrock", map[string]string{
					state.ConfigKeyAuthType: state.AuthTypeSigV4,
				})
			},
			errorContains: "credentials enrichment failed",
		},
		{
			name:              "missing aws credentials returns error",
			secrets:           []*corev1.Secret{testSecret("default", "bedrock-creds", map[string]string{"wrong-field": "value"})},
			prepareCycleState: func() *framework.CycleState { return newBedrockCycleState("default", "bedrock-creds") },
			errorContains:     "failed to generate auth headers",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newSecretStore()
			for _, secret := range test.secrets {
				require.NoError(t, store.addOrUpdate(secret.GetNamespace(), secret.GetName(), secret))
			}

			plugin := newTestPlugin(store)
			request := newBedrockRequest()
			err := plugin.ProcessRequest(context.Background(), test.prepareCycleState(), request)

			if test.errorContains != "" {
				require.ErrorContains(t, err, test.errorContains)
				return
			}
			require.NoError(t, err)

			// SigV4 Authorization is dynamic (timestamp, signature), so we verify the scheme prefix only.
			require.True(t, strings.HasPrefix(request.Headers["Authorization"], "AWS4-HMAC-SHA256"),
				"Authorization header should start with AWS4-HMAC-SHA256, got: %s", request.Headers["Authorization"])
			require.NotEmpty(t, request.Headers["X-Amz-Date"])
			require.NotEmpty(t, request.Headers["X-Amz-Content-Sha256"])

			if diff := cmp.Diff(test.wantSecurityToken, request.Headers["X-Amz-Security-Token"]); diff != "" {
				t.Errorf("X-Amz-Security-Token mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
