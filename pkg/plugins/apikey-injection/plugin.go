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
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/gateway-api-inference-extension/pkg/bbr/framework"
	errcommon "sigs.k8s.io/gateway-api-inference-extension/pkg/common/error"
	logutil "sigs.k8s.io/gateway-api-inference-extension/pkg/common/observability/logging"
	"sigs.k8s.io/gateway-api-inference-extension/pkg/epp/framework/interface/plugin"

	"github.com/opendatahub-io/ai-gateway-payload-processing/pkg/plugins/apikey-injection/auth"
	"github.com/opendatahub-io/ai-gateway-payload-processing/pkg/plugins/common/state"
)

// credentialsEnricherFunc augments the credentials map with per-request data
// (e.g. request body, endpoint) before it is passed to the AuthHeadersGenerator.
// Enrichers MUST return a new map and never mutate the original (which is shared
// across requests via the secretStore).
type credentialsEnricherFunc func(credentials map[string]string, cycleState *framework.CycleState, request *framework.InferenceRequest) (map[string]string, error)

const (
	// APIKeyInjectionPluginType is the registered name for this plugin in the BBR registry.
	APIKeyInjectionPluginType = "apikey-injection"
)

// compile-time interface check
var _ framework.RequestProcessor = &ApiKeyInjectionPlugin{}

// APIKeyInjectionFactory defines the factory function for ApiKeyInjectionPlugin.
func APIKeyInjectionFactory(name string, _ json.RawMessage, handle framework.Handle) (framework.BBRPlugin, error) {
	plugin, err := NewAPIKeyInjectionPlugin(handle.ReconcilerBuilder, handle.Client())
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin '%s' - %w", APIKeyInjectionPluginType, err)
	}

	return plugin.WithName(name), nil
}

// NewAPIKeyInjectionPlugin creates a new apiKeyInjectionPlugin and returns its pointer
func NewAPIKeyInjectionPlugin(reconcilerBuilder func() *builder.Builder, clientReader client.Reader) (*ApiKeyInjectionPlugin, error) {
	store := newSecretStore()
	reconciler := &secretReconciler{
		Reader: clientReader,
		store:  store,
	}

	if err := reconcilerBuilder().For(&corev1.Secret{}).WithEventFilter(managedLabelPredicate()).Complete(reconciler); err != nil {
		return nil, fmt.Errorf("failed to register Secret reconciler for plugin '%s' - %w", APIKeyInjectionPluginType, err)
	}

	return (&ApiKeyInjectionPlugin{
		typedName: plugin.TypedName{
			Type: APIKeyInjectionPluginType,
			Name: APIKeyInjectionPluginType,
		},
		// Auth generators keyed by auth-type. Each generator is stateless and reads
		// its configuration from the providerConfig parameter at request time.
		authHeadersGenerators: map[string]auth.AuthHeadersGenerator{
			state.AuthTypeSimple:   &auth.SimpleAuthGenerator{},
			state.AuthTypeGCPOAuth: &auth.GCPOAuth2Generator{},
			state.AuthTypeSigV4:    &auth.SigV4AuthGenerator{},
<<<<<<< Updated upstream
		},
		dataEnrichers: map[string]credentialsEnricherFunc{
			state.AuthTypeSigV4: enrichBedrockCredentials,
=======
>>>>>>> Stashed changes
		},
		store: store,
	}), nil
}

// ApiKeyInjectionPlugin injects an API key from a Kubernetes Secret into the request headers.
// The Secret is identified by its namespaced name from CycleState. The provider (e.g., openai, anthropic)
// determines which header name and value format are used.
// Providers that require per-request data for authentication (e.g. SigV4) register a
// credentialsEnricherFunc in dataEnrichers to augment the credentials map before signing.
type ApiKeyInjectionPlugin struct {
	typedName             plugin.TypedName
	authHeadersGenerators map[string]auth.AuthHeadersGenerator
	dataEnrichers         map[string]credentialsEnricherFunc
	store                 *secretStore
}

// TypedName returns the type and name tuple of this plugin instance.
func (p *ApiKeyInjectionPlugin) TypedName() plugin.TypedName {
	return p.typedName
}

// WithName sets the name of this plugin instance.
func (p *ApiKeyInjectionPlugin) WithName(name string) *ApiKeyInjectionPlugin {
	p.typedName.Name = name
	return p
}

// ProcessRequest reads the credential Secret reference and provider config from CycleState
// (written by model-provider-resolver), looks up credentials in the store, determines the
// auth type, and injects provider-specific auth headers into the request.
func (p *ApiKeyInjectionPlugin) ProcessRequest(ctx context.Context, cycleState *framework.CycleState, request *framework.InferenceRequest) error {
	logger := log.FromContext(ctx).V(logutil.DEFAULT)

	// Check if this is an external model (provider set by model-provider-resolver).
	// Internal models have no provider in CycleState and don't need API key injection.
	providerName, err := framework.ReadCycleStateKey[string](cycleState, state.ProviderKey)
	if err != nil || providerName == "" {
		return nil
	}

	credsName, err := framework.ReadCycleStateKey[string](cycleState, state.CredsRefName)
	if err != nil || credsName == "" {
		logger.Error(err, "credentialRef name missing", "provider", providerName)
		return errcommon.Error{Code: errcommon.Internal, Msg: fmt.Sprintf("provider '%s' is missing credentialRef", providerName)}
	}
	credsNamespace, err := framework.ReadCycleStateKey[string](cycleState, state.CredsRefNamespace)
	if err != nil || credsNamespace == "" {
		logger.Error(err, "credentialRef namespace missing", "provider", providerName)
		return errcommon.Error{Code: errcommon.Internal, Msg: fmt.Sprintf("provider '%s' is missing credentialRef namespace", providerName)}
	}

	credentials, found := p.store.get(credsNamespace, credsName)
	if !found {
		logger.Error(nil, "credentials not found in store", "provider", providerName)
		return errcommon.Error{Code: errcommon.Internal, Msg: fmt.Sprintf("provider '%s' credentials not found", providerName)}
	}

	// Read provider config from CycleState (may be nil if not set)
	providerConfig, _ := framework.ReadCycleStateKey[map[string]string](cycleState, state.ProviderConfigKey)

	// Determine auth type from config, default to simple-auth
	authType := state.AuthTypeSimple
	if providerConfig != nil {
		if at, ok := providerConfig[state.ConfigKeyAuthType]; ok && at != "" {
			authType = at
		}
	}

<<<<<<< Updated upstream
	// Apply credentials enricher if one is registered for this auth type
	if enricher, ok := p.dataEnrichers[authType]; ok {
		var enrichErr error
		credentials, enrichErr = enricher(credentials, cycleState, request)
		if enrichErr != nil {
			return errcommon.Error{Code: errcommon.Internal, Msg: fmt.Sprintf("credentials enrichment failed for auth type '%s': %v", authType, enrichErr)}
		}
	}

=======
>>>>>>> Stashed changes
	generator, ok := p.authHeadersGenerators[authType]
	if !ok {
		logger.Error(nil, "unsupported auth type", "authType", authType, "provider", providerName)
		return errcommon.Error{Code: errcommon.Internal, Msg: fmt.Sprintf("unsupported auth type '%s' for provider '%s'", authType, providerName)}
	}

	authHeaders, err := generator.GenerateAuthHeaders(credentials, providerConfig)
	if err != nil {
		logger.Error(err, "auth header generation failed", "authType", authType, "provider", providerName)
		return errcommon.Error{Code: errcommon.Internal, Msg: fmt.Sprintf("failed to generate auth headers for provider '%s': %v", providerName, err)}
	}

	for headerKey, headerValue := range authHeaders {
		request.SetHeader(headerKey, headerValue)
	}

	logger.Info("auth headers injected", "authType", authType, "provider", providerName)
	return nil
}

// enrichBedrockCredentials copies the credentials map and adds per-request fields
// needed by SigV4 signing: the serialized request body, target endpoint, and request path.
func enrichBedrockCredentials(credentials map[string]string, cycleState *framework.CycleState, request *framework.InferenceRequest) (map[string]string, error) {
	enriched := make(map[string]string, len(credentials)+3)
	for k, v := range credentials {
		enriched[k] = v
	}

	// json.Marshal produces deterministic output (sorted map keys), ensuring the
	// signed body matches what the framework sends upstream.
	bodyBytes, err := json.Marshal(request.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	enriched["_request_body"] = string(bodyBytes)

	endpoint, err := framework.ReadCycleStateKey[string](cycleState, state.EndpointKey)
	if err != nil || endpoint == "" {
		return nil, fmt.Errorf("missing or empty endpoint in CycleState (key %q)", state.EndpointKey)
	}
	enriched["_endpoint"] = endpoint

	if path := request.Headers[":path"]; path != "" {
		enriched["_path"] = path
	}

	return enriched, nil
}
