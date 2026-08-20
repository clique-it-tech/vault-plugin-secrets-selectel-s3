package selectel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const credentialNamePrefix = "vault-"

func (b *selectelBackend) s3Credential() *framework.Secret {
	return &framework.Secret{
		Type: secretTypeS3Credential,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "S3 access key id.",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "S3 secret access key.",
			},
		},
		Revoke: b.credentialRevoke,
		Renew:  b.credentialRenew,
	}
}

func pathCredentials(b *selectelBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSelectel,
			OperationVerb:   "generate",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Role that decides which service user the key belongs to.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Issue an S3 access key for one role.",
		HelpDescription: "The service user comes from the role, not from this request.",
	}
}

func (b *selectelBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("role").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(roleNotFound(name).Error()), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return logical.ErrorResponse(errMissingConfig.Error()), nil
		}
		return nil, err
	}

	created, err := c.createCredential(ctx, role.ServiceUserID, &credentialRequest{
		Name:      fmt.Sprintf("%s%s-%d", credentialNamePrefix, name, time.Now().UnixNano()),
		ProjectID: role.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create the s3 credential: %w", err)
	}

	resp := b.Secret(secretTypeS3Credential).Response(
		map[string]any{
			"access_key": created.AccessKey,
			"secret_key": created.SecretKey,
		},
		map[string]any{
			"access_key":      created.AccessKey,
			"service_user_id": role.ServiceUserID,
		},
	)

	// Vault clamps both of these to the mount's own limits, so the role decides
	// the shape and the operator keeps the last word. Set max_lease_ttl on the
	// mount deliberately: a Selectel key has no expiry of its own, and the lease
	// is the only thing that ends it.
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *selectelBackend) credentialRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	accessKey, err := internalString(req.Secret.InternalData, "access_key")
	if err != nil {
		return nil, err
	}
	userID, err := internalString(req.Secret.InternalData, "service_user_id")
	if err != nil {
		return nil, err
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := c.deleteCredential(ctx, userID, accessKey); err != nil && !errors.Is(err, errCredentialNotFound) {
		return nil, fmt.Errorf("could not delete the s3 credential: %w", err)
	}

	return nil, nil
}

func (b *selectelBackend) credentialRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = req.Secret.Increment
	return resp, nil
}

func internalString(data map[string]any, key string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("lease is missing %s", key)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("unexpected type %T for %s", raw, key)
	}
	return value, nil
}
