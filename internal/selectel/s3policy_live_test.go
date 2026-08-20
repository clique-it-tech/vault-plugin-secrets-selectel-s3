package selectel

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestLiveBucketPolicyRoundTrip signs a real request against Selectel. Unit
// tests cannot catch a signing mistake because the fake server never verifies
// the signature, and a broken signature only shows up on requests with a body.
// It reads the policy and writes back exactly what it read, so a run leaves the
// bucket as it found it.
//
// Run it with credentials of a service user that the bucket policy names:
//
//	SELECTEL_LIVE_BUCKET=aether SELECTEL_LIVE_ENDPOINT=https://s3.ru-7.storage.selcloud.ru \
//	SELECTEL_LIVE_READ_ACCESS_KEY=...  SELECTEL_LIVE_READ_SECRET_KEY=... \
//	SELECTEL_LIVE_WRITE_ACCESS_KEY=... SELECTEL_LIVE_WRITE_SECRET_KEY=... \
//	go test ./internal/selectel -run Live -v
//
// The reader must be a principal the policy names; the writer needs s3.admin.
// Selectel lets neither do the other half, which is why this takes two keys.
func TestLiveBucketPolicyRoundTrip(t *testing.T) {
	bucket := os.Getenv("SELECTEL_LIVE_BUCKET")
	endpoint := os.Getenv("SELECTEL_LIVE_ENDPOINT")
	readAccess := os.Getenv("SELECTEL_LIVE_READ_ACCESS_KEY")
	readSecret := os.Getenv("SELECTEL_LIVE_READ_SECRET_KEY")
	writeAccess := os.Getenv("SELECTEL_LIVE_WRITE_ACCESS_KEY")
	writeSecret := os.Getenv("SELECTEL_LIVE_WRITE_SECRET_KEY")
	if bucket == "" || endpoint == "" || readAccess == "" || writeAccess == "" {
		t.Skip("set SELECTEL_LIVE_* to run this against a real bucket")
	}

	region := os.Getenv("SELECTEL_LIVE_REGION")
	if region == "" {
		region = "ru-7"
	}

	ctx := context.Background()
	reader := newS3Client(endpoint, region, readAccess, readSecret)
	writer := newS3Client(endpoint, region, writeAccess, writeSecret)

	before, err := reader.getBucketPolicy(ctx, bucket)
	if err != nil {
		t.Fatalf("could not read the policy: %v", err)
	}
	if len(before.Statement) == 0 {
		t.Fatalf("expected %s to have a policy already", bucket)
	}

	if err := writer.putBucketPolicy(ctx, bucket, before); err != nil {
		t.Fatalf("could not write the policy back: %v", err)
	}

	after, err := reader.getBucketPolicy(ctx, bucket)
	if err != nil {
		t.Fatalf("could not read the policy back: %v", err)
	}

	if normalise(t, before) != normalise(t, after) {
		want, _ := json.Marshal(before)
		got, _ := json.Marshal(after)
		t.Fatalf("the policy changed:\n before %s\n after  %s", want, got)
	}
}

// normalise sorts the parts Selectel is free to reorder, so a round trip is
// compared on content rather than on the order it happened to come back in.
func normalise(t *testing.T, policy *bucketPolicy) string {
	t.Helper()

	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("could not encode the policy: %v", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("could not decode the policy: %v", err)
	}

	for _, statement := range generic["Statement"].([]any) {
		fields := statement.(map[string]any)
		for _, key := range []string{"Action", "Resource"} {
			if list, ok := fields[key].([]any); ok {
				items := make([]string, 0, len(list))
				for _, item := range list {
					items = append(items, item.(string))
				}
				slices.Sort(items)
				fields[key] = items
			}
		}
		if principal, ok := fields["Principal"].(map[string]any); ok {
			if list, ok := principal["AWS"].([]any); ok {
				items := make([]string, 0, len(list))
				for _, item := range list {
					items = append(items, item.(string))
				}
				slices.Sort(items)
				principal["AWS"] = items
			}
		}
	}

	sorted, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("could not encode the sorted policy: %v", err)
	}
	return string(sorted)
}
