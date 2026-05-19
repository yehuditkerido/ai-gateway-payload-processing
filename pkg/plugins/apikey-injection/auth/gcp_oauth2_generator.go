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

package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// gcpServiceAccountField is the field name in the credentials map that holds
// the GCP Service Account JSON content.
const gcpServiceAccountField = "gcp-service-account-json"

// vertexAIScope is the OAuth2 scope required for Vertex AI API access.
const vertexAIScope = "https://www.googleapis.com/auth/cloud-platform"

// compile-time interface check
var _ AuthHeadersGenerator = &GCPOAuth2Generator{}

// cachedToken holds an OAuth2 token with its expiration time.
type cachedToken struct {
	token     *oauth2.Token
	expiresAt time.Time
}

// GCPOAuth2Generator generates OAuth2 access tokens for GCP services.
// It reads a Service Account JSON from the credentials, generates an OAuth2 token,
// and caches it per-credentials to avoid unnecessary token refreshes.
// HeaderName is the HTTP header (e.g. "Authorization").
// HeaderValuePrefix is prepended to the token (e.g. "Bearer "); use "" for raw tokens.
type GCPOAuth2Generator struct {
	HeaderName        string
	HeaderValuePrefix string

	mu    sync.RWMutex
	cache map[string]*cachedToken
}

// GenerateAuthHeaders reads the GCP Service Account JSON from credentials,
// generates (or retrieves cached) OAuth2 access token, and returns the
// Authorization header. Configuration can be overridden via providerConfig.
func (g *GCPOAuth2Generator) GenerateAuthHeaders(credentials map[string]string, providerConfig map[string]string) (map[string]string, error) {
	serviceAccountJSON, ok := credentials[gcpServiceAccountField]
	if !ok {
		return nil, fmt.Errorf("credentials missing required field %s", gcpServiceAccountField)
	}

	token, err := g.getOrRefreshToken(serviceAccountJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth2 token: %w", err)
	}

	headerName := getConfigOrDefault(providerConfig, ConfigKeyHeaderName, "Authorization")
	headerValuePrefix := getConfigOrDefault(providerConfig, ConfigKeyHeaderValuePrefix, "Bearer ")

	return map[string]string{
		headerName: fmt.Sprintf("%s%s", headerValuePrefix, token.AccessToken),
	}, nil
}

// getOrRefreshToken returns a cached token if valid, or generates a new one.
// Uses the service account JSON as the cache key.
func (g *GCPOAuth2Generator) getOrRefreshToken(serviceAccountJSON string) (*oauth2.Token, error) {
	g.mu.RLock()
	cached, exists := g.cache[serviceAccountJSON]
	g.mu.RUnlock()

	if exists && g.isTokenValid(cached) {
		return cached.token, nil
	}

	return g.refreshToken(serviceAccountJSON)
}

// isTokenValid checks if the cached token is still valid with a safety margin.
// Returns false if token will expire within 5 minutes.
func (g *GCPOAuth2Generator) isTokenValid(cached *cachedToken) bool {
	if cached == nil || cached.token == nil {
		return false
	}
	return time.Now().Add(5 * time.Minute).Before(cached.expiresAt)
}

// refreshToken generates a new OAuth2 token from the service account JSON.
func (g *GCPOAuth2Generator) refreshToken(serviceAccountJSON string) (*oauth2.Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Lazy initialization of cache (allows struct literal without constructor)
	if g.cache == nil {
		g.cache = make(map[string]*cachedToken)
	}

	// Double-check after acquiring write lock
	if cached, exists := g.cache[serviceAccountJSON]; exists && g.isTokenValid(cached) {
		return cached.token, nil
	}

	ctx := context.Background()
	creds, err := google.CredentialsFromJSONWithType(ctx, []byte(serviceAccountJSON), google.ServiceAccount, vertexAIScope)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service account JSON: %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain OAuth2 token: %w", err)
	}

	g.cache[serviceAccountJSON] = &cachedToken{
		token:     token,
		expiresAt: token.Expiry,
	}

	return token, nil
}
