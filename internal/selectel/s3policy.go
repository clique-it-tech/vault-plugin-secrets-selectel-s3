package selectel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	vaultStatementID = "allow-vault-issued"
	s3Service        = "s3"
)

var bucketActions = []string{
	"s3:AbortMultipartUpload",
	"s3:DeleteObject",
	"s3:GetBucketCORS",
	"s3:GetBucketPolicy",
	"s3:GetBucketLocation",
	"s3:GetBucketVersioning",
	"s3:GetObject",
	"s3:GetObjectVersion",
	"s3:ListBucket",
	"s3:ListBucketMultipartUploads",
	"s3:ListBucketVersions",
	"s3:ListMultipartUploadParts",
	"s3:PutObject",
}

type policyStatement struct {
	Sid       string         `json:"Sid,omitempty"`
	Effect    string         `json:"Effect"`
	Principal map[string]any `json:"Principal,omitempty"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}

type bucketPolicy struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type s3Client struct {
	http      *http.Client
	endpoint  string
	region    string
	accessKey string
	secretKey string
}

func newS3Client(endpoint, region, accessKey, secretKey string) *s3Client {
	return &s3Client{
		http:      &http.Client{Timeout: requestTimeout},
		endpoint:  strings.TrimSuffix(endpoint, "/"),
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
	}
}

func (c *s3Client) send(ctx context.Context, method, bucket, query string, body []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", c.endpoint, bucket)
	if query != "" {
		url += "?" + query
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	// S3 rebuilds the canonical request from this header, so it has to be on the
	// wire as well as in the signature, or every request with a body comes back
	// as SignatureDoesNotMatch.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	creds := aws.Credentials{AccessKeyID: c.accessKey, SecretAccessKey: c.secretKey}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err := signer.SignHTTP(ctx, creds, req, payloadHash, s3Service, c.region, time.Now().UTC()); err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoBucketPolicy
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("s3 returned %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

var errNoBucketPolicy = errors.New("bucket has no policy yet")

func (c *s3Client) getBucketPolicy(ctx context.Context, bucket string) (*bucketPolicy, error) {
	payload, err := c.send(ctx, http.MethodGet, bucket, "policy", nil)
	if errors.Is(err, errNoBucketPolicy) {
		return &bucketPolicy{Version: "2012-10-17"}, nil
	}
	if err != nil {
		return nil, err
	}

	policy := new(bucketPolicy)
	if err := json.Unmarshal(payload, policy); err != nil {
		return nil, fmt.Errorf("could not read the bucket policy: %w", err)
	}
	if policy.Version == "" {
		policy.Version = "2012-10-17"
	}
	return policy, nil
}

func (c *s3Client) putBucketPolicy(ctx context.Context, bucket string, policy *bucketPolicy) error {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	_, err = c.send(ctx, http.MethodPut, bucket, "policy", encoded)
	return err
}

func principals(st policyStatement) []string {
	raw, ok := st.Principal["AWS"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func vaultStatement(policy *bucketPolicy) int {
	for i, st := range policy.Statement {
		if st.Sid == vaultStatementID {
			return i
		}
	}
	return -1
}

func grantBucketAccess(policy *bucketPolicy, bucket, userID string) bool {
	resource := []any{fmt.Sprintf("arn:aws:s3:::%s", bucket), fmt.Sprintf("arn:aws:s3:::%s/*", bucket)}
	actions := make([]any, 0, len(bucketActions))
	for _, a := range bucketActions {
		actions = append(actions, a)
	}

	at := vaultStatement(policy)
	if at < 0 {
		policy.Statement = append(policy.Statement, policyStatement{
			Sid:       vaultStatementID,
			Effect:    "Allow",
			Principal: map[string]any{"AWS": []any{userID}},
			Action:    actions,
			Resource:  resource,
		})
		return true
	}

	existing := principals(policy.Statement[at])
	if slices.Contains(existing, userID) {
		return false
	}

	updated := make([]any, 0, len(existing)+1)
	for _, p := range existing {
		updated = append(updated, p)
	}
	updated = append(updated, userID)
	policy.Statement[at].Principal = map[string]any{"AWS": updated}
	policy.Statement[at].Action = actions
	policy.Statement[at].Resource = resource
	return true
}

func revokeBucketAccess(policy *bucketPolicy, userID string) bool {
	at := vaultStatement(policy)
	if at < 0 {
		return false
	}

	existing := principals(policy.Statement[at])
	if !slices.Contains(existing, userID) {
		return false
	}

	kept := make([]any, 0, len(existing))
	for _, p := range existing {
		if p != userID {
			kept = append(kept, p)
		}
	}

	if len(kept) == 0 {
		policy.Statement = slices.Delete(policy.Statement, at, at+1)
		return true
	}

	policy.Statement[at].Principal = map[string]any{"AWS": kept}
	return true
}
