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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestSimpleAuthHeadersGenerator(t *testing.T) {
	tests := []struct {
		name           string
		providerConfig map[string]string
		credentials    map[string]string
		wantHeaders    map[string]string
		wantErr        bool
	}{
		{
			name: "defaults - Bearer prefix (OpenAI style)",
			providerConfig: nil,
			credentials:    map[string]string{"api-key": "sk-test-key"},
			wantHeaders: map[string]string{
				"Authorization": "Bearer sk-test-key",
			},
		},
		{
			name: "custom header name (Anthropic style)",
			providerConfig: map[string]string{
				"header-name":         "x-api-key",
				"header-value-prefix": "",
			},
			credentials: map[string]string{"api-key": "ant-key-123"},
			wantHeaders: map[string]string{
				"x-api-key": "ant-key-123",
			},
		},
		{
			name: "custom header name (Azure style)",
			providerConfig: map[string]string{
				"header-name":         "api-key",
				"header-value-prefix": "",
			},
			credentials: map[string]string{"api-key": "azure-key-456"},
			wantHeaders: map[string]string{
				"api-key": "azure-key-456",
			},
		},
		{
			name: "custom secret key",
			providerConfig: map[string]string{
				"secret-key": "custom-key",
			},
			credentials: map[string]string{"custom-key": "custom-value"},
			wantHeaders: map[string]string{
				"Authorization": "Bearer custom-value",
			},
		},
		{
			name:           "missing api-key field returns error",
			providerConfig: nil,
			credentials:    map[string]string{"wrong-field": "some-value"},
			wantErr:        true,
		},
		{
			name:           "empty credentials returns error",
			providerConfig: nil,
			credentials:    map[string]string{},
			wantErr:        true,
		},
		{
			name: "custom secret key missing returns error",
			providerConfig: map[string]string{
				"secret-key": "custom-key",
			},
			credentials: map[string]string{"api-key": "value"},
			wantErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := &SimpleAuthGenerator{}
			authHeaders, err := generator.GenerateAuthHeaders(test.credentials, test.providerConfig)

			if test.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if diff := cmp.Diff(test.wantHeaders, authHeaders, cmpopts.SortMaps(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("headers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
