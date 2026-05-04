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
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	awsAccessKeyField     = "aws-access-key-id"
	awsSecretKeyField     = "aws-secret-access-key"
	awsSessionTokenField  = "aws-session-token"
	enrichedBodyField     = "_request_body"
	enrichedEndpointField = "_endpoint"
	enrichedPathField     = "_path"
	bedrockService        = "bedrock"
	defaultPath           = "/v1/chat/completions"
)

// compile-time interface check
var _ AuthHeadersGenerator = &SigV4AuthGenerator{}

// SigV4AuthGenerator generates AWS Signature Version 4 authentication headers.
// All inputs (credentials, request body, endpoint) come from the credentialsData map,
// where request-specific fields are injected by the credentials enricher.
type SigV4AuthGenerator struct{}

// GenerateAuthHeaders computes a SigV4 signature and returns the required AWS auth headers.
// Expects the following keys in credentialsData:
//   - "aws-access-key-id" and "aws-secret-access-key" (from the Kubernetes Secret)
//   - "_request_body" and "_endpoint" (injected by the credentials enricher)
//   - "aws-session-token" (optional, for temporary credentials)
func (g *SigV4AuthGenerator) GenerateAuthHeaders(credentialsData map[string]string) (map[string]string, error) {
	accessKey, ok := credentialsData[awsAccessKeyField]
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("credentials missing required field %s", awsAccessKeyField)
	}
	secretKey, ok := credentialsData[awsSecretKeyField]
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("credentials missing required field %s", awsSecretKeyField)
	}

	body, ok := credentialsData[enrichedBodyField]
	if !ok {
		return nil, fmt.Errorf("credentials missing required field %s (enricher not applied?)", enrichedBodyField)
	}
	endpoint, ok := credentialsData[enrichedEndpointField]
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("credentials missing required field %s (enricher not applied?)", enrichedEndpointField)
	}

	region, err := regionFromEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to extract region: %w", err)
	}

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    credentialsData[awsSessionTokenField],
		Source:          "ExternalModelSecret",
	}

	bodyHash := sha256Hex([]byte(body))

	path := credentialsData[enrichedPathField]
	if path == "" {
		path = defaultPath
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+endpoint+path, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request for signing: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	signer := v4.NewSigner()
	if err := signer.SignHTTP(context.Background(), creds, req, bodyHash, bedrockService, region, time.Now()); err != nil {
		return nil, fmt.Errorf("SigV4 signing failed: %w", err)
	}

	headers := map[string]string{
		"Authorization":        req.Header.Get("Authorization"),
		"X-Amz-Date":           req.Header.Get("X-Amz-Date"),
		"X-Amz-Content-Sha256": bodyHash,
	}
	if creds.SessionToken != "" {
		headers["X-Amz-Security-Token"] = creds.SessionToken
	}

	return headers, nil
}

// regionFromEndpoint extracts the AWS region from a Bedrock endpoint hostname.
// e.g. "bedrock-runtime.us-east-1.amazonaws.com" → "us-east-1"
func regionFromEndpoint(endpoint string) (string, error) {
	parts := strings.Split(endpoint, ".")
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid AWS endpoint format: %q (expected service.region.amazonaws.com)", endpoint)
	}
	return parts[1], nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}
