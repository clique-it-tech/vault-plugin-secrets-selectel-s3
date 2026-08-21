package selectel

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathDropStatement(b *selectelBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/drop-statement/" + framework.GenericNameRegex("bucket"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSelectel,
			OperationVerb:   "drop",
			OperationSuffix: "bucket-statement",
		},
		Fields: map[string]*framework.FieldSchema{
			"bucket": {
				Type:        framework.TypeString,
				Description: "Bucket whose policy is edited.",
				Required:    true,
			},
			"project_id": {
				Type:        framework.TypeString,
				Description: "Project the bucket belongs to.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Project id",
				},
			},
			"sids": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Sids of the statements to remove. Nothing else in the policy is touched.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Statements to remove",
					Value: "allow-all-sa",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathDropStatement},
		},
		HelpSynopsis: "Remove named statements from a bucket policy.",
		HelpDescription: `Buckets that predate the engine often carry a blanket statement granting
every principal in the account full access. This removes statements you name and leaves the rest
alone, so a deliberately public rule such as anonymous GetObject for a CDN survives. The engine's
own statements cannot be removed this way: dropping them would cost it the access it needs to
manage the bucket at all.`,
	}
}

func (b *selectelBackend) pathDropStatement(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	bucket := data.Get("bucket").(string)
	projectID := data.Get("project_id").(string)
	if projectID == "" {
		return logical.ErrorResponse("project_id is required"), nil
	}

	sids := data.Get("sids").([]string)
	if len(sids) == 0 {
		return logical.ErrorResponse("name at least one sid to remove"), nil
	}
	for _, sid := range sids {
		if sid == vaultStatementID || sid == readerStatementID {
			return logical.ErrorResponse(
				"%s belongs to the engine; removing it would cost the engine access to %s", sid, bucket), nil
		}
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

	role := &selectelRole{Bucket: bucket, ProjectID: projectID}
	policy, err := b.readBucketPolicy(ctx, c, role, config)
	if err != nil {
		return nil, fmt.Errorf("could not read the policy of %s, adopt the bucket first: %w", bucket, err)
	}

	removed, missing := dropStatements(policy, sids)
	if len(policy.Statement) == 0 {
		return logical.ErrorResponse("that would leave %s with an empty policy", bucket), nil
	}

	if len(removed) > 0 {
		if err := c.withS3Admin(ctx, projectID, config.S3Endpoint, config.S3Region, func(s3 *s3Client) error {
			return s3.putBucketPolicy(ctx, bucket, policy)
		}); err != nil {
			return nil, fmt.Errorf("could not write the policy of %s: %w", bucket, err)
		}
	}

	remaining := make([]string, 0, len(policy.Statement))
	for _, st := range policy.Statement {
		remaining = append(remaining, st.Sid)
	}

	return &logical.Response{Data: map[string]any{
		"bucket":    bucket,
		"removed":   removed,
		"not_found": missing,
		"remaining": remaining,
	}}, nil
}

func dropStatements(policy *bucketPolicy, sids []string) (removed, missing []string) {
	removed, missing = make([]string, 0, len(sids)), make([]string, 0)
	kept := policy.Statement[:0]
	for _, st := range policy.Statement {
		if slices.Contains(sids, st.Sid) {
			removed = append(removed, st.Sid)
			continue
		}
		kept = append(kept, st)
	}
	policy.Statement = kept
	for _, sid := range sids {
		if !slices.Contains(removed, sid) {
			missing = append(missing, sid)
		}
	}
	return removed, missing
}
