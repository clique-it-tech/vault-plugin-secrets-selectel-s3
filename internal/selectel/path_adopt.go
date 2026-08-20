package selectel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAdoptBucket(b *selectelBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/adopt-bucket/" + framework.GenericNameRegex("bucket"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSelectel,
			OperationVerb:   "adopt",
			OperationSuffix: "bucket",
		},
		Fields: map[string]*framework.FieldSchema{
			"bucket": {
				Type:        framework.TypeString,
				Description: "Bucket the engine should take over.",
				Required:    true,
			},
			"project_id": {
				Type:        framework.TypeString,
				Description: "Project the bucket belongs to.",
				Required:    true,
			},
			"policy": {
				Type: framework.TypeString,
				Description: "The bucket's current policy, as JSON. Read it with any key the policy " +
					"already names. Leave it out if the engine can already read the bucket.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAdoptBucket},
		},
		HelpSynopsis: "Introduce the engine to a bucket it cannot read yet.",
		HelpDescription: `Selectel shows a bucket policy only to a principal the policy already names,
and refuses the read even to s3.admin. A bucket that predates the engine therefore has to be handed
over once: pass its current policy and the engine writes itself in, keeping every statement it was
given. From then on the engine reads and updates that bucket on its own, and adopting it again is
a no-op.`,
	}
}

func (b *selectelBackend) pathAdoptBucket(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	bucket := data.Get("bucket").(string)
	projectID := data.Get("project_id").(string)
	if projectID == "" {
		return logical.ErrorResponse("project_id is required"), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse(errMissingConfig.Error()), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return logical.ErrorResponse(errMissingConfig.Error()), nil
		}
		return nil, err
	}

	reader, err := c.readerUser(ctx, projectID)
	if err != nil {
		return nil, err
	}

	policy, err := b.adoptedPolicy(ctx, c, config, bucket, projectID, data)
	if err != nil {
		return nil, err
	}

	if !grantPolicyRead(policy, bucket, reader.ID) {
		return &logical.Response{Data: map[string]any{
			"bucket":  bucket,
			"reader":  reader.ID,
			"adopted": true,
			"changed": false,
		}}, nil
	}

	if err := c.withS3Admin(ctx, projectID, config.S3Endpoint, config.S3Region, func(s3 *s3Client) error {
		return s3.putBucketPolicy(ctx, bucket, policy)
	}); err != nil {
		return nil, fmt.Errorf("could not write the policy of %s: %w", bucket, err)
	}

	if err := b.confirmAdoption(ctx, c, config, bucket, projectID); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]any{
		"bucket":  bucket,
		"reader":  reader.ID,
		"adopted": true,
		"changed": true,
	}}, nil
}

// adoptedPolicy prefers what the engine can read itself, so adopting a bucket
// twice cannot roll it back to a policy the caller pasted from an older state.
func (b *selectelBackend) adoptedPolicy(ctx context.Context, c *client, config *selectelConfig, bucket, projectID string, data *framework.FieldData) (*bucketPolicy, error) {
	role := &selectelRole{Bucket: bucket, ProjectID: projectID}
	if policy, err := b.readBucketPolicy(ctx, c, role, config); err == nil {
		return policy, nil
	}

	raw, ok := data.GetOk("policy")
	if !ok {
		return nil, errors.New(
			"the engine cannot read this bucket yet, so pass its current policy in the policy field: " +
				"read it with any key the policy already names, for example aws s3api get-bucket-policy")
	}

	policy := new(bucketPolicy)
	if err := json.Unmarshal([]byte(raw.(string)), policy); err != nil {
		return nil, fmt.Errorf("the policy field is not valid json: %w", err)
	}
	if len(policy.Statement) == 0 {
		return nil, errors.New("the policy you passed has no statements, which would empty the bucket policy")
	}
	if policy.Version == "" {
		policy.Version = "2012-10-17"
	}
	return policy, nil
}

// confirmAdoption proves the engine can now read the bucket, so a caller never
// walks away believing a bucket was adopted when it was not.
func (b *selectelBackend) confirmAdoption(ctx context.Context, c *client, config *selectelConfig, bucket, projectID string) error {
	role := &selectelRole{Bucket: bucket, ProjectID: projectID}
	if _, err := b.readBucketPolicy(ctx, c, role, config); err != nil {
		return fmt.Errorf("the policy was written but the engine still cannot read %s: %w", bucket, err)
	}
	return nil
}
