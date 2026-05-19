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
	"fmt"
)

// Config keys for SimpleAuthGenerator in ExternalProvider.spec.config
const (
	ConfigKeyHeaderName        = "header-name"
	ConfigKeyHeaderValuePrefix = "header-value-prefix"
	ConfigKeySecretKey         = "secret-key"
)

// Defaults for SimpleAuthGenerator
const (
	defaultHeaderName        = "Authorization"
	defaultHeaderValuePrefix = "Bearer "
	defaultSecretKey         = "api-key"
)

// compile-time interface check
var _ AuthHeadersGenerator = &SimpleAuthGenerator{}

// SimpleAuthGenerator generates a single auth header from an API key.
// Configuration is read from providerConfig at request time:
//   - header-name: HTTP header name (default: "Authorization")
//   - header-value-prefix: prefix prepended to the key (default: "Bearer ")
//   - secret-key: key in the credentials Secret (default: "api-key")
type SimpleAuthGenerator struct{}

// GenerateAuthHeaders extracts the API key from credentials using the configured
// secret-key and returns the header name/value using providerConfig settings.
func (g *SimpleAuthGenerator) GenerateAuthHeaders(credentials map[string]string, providerConfig map[string]string) (map[string]string, error) {
	headerName := getConfigOrDefault(providerConfig, ConfigKeyHeaderName, defaultHeaderName)
	headerValuePrefix := getConfigOrDefault(providerConfig, ConfigKeyHeaderValuePrefix, defaultHeaderValuePrefix)
	secretKey := getConfigOrDefault(providerConfig, ConfigKeySecretKey, defaultSecretKey)

	apiKey, ok := credentials[secretKey]
	if !ok {
		return nil, fmt.Errorf("credentials missing required field %s", secretKey)
	}

	return map[string]string{
		headerName: fmt.Sprintf("%s%s", headerValuePrefix, apiKey),
	}, nil
}

// getConfigOrDefault returns the value from config if the key is present,
// otherwise returns the default value. An empty string is a valid override.
func getConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if config == nil {
		return defaultValue
	}
	if val, ok := config[key]; ok {
		return val
	}
	return defaultValue
}
