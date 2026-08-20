package selectel

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSweep(b *selectelBackend) *framework.Path {
	return &framework.Path{
		Pattern: "sweep/" + framework.GenericNameRegex("role"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSelectel,
			OperationVerb:   "sweep",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Role whose service user is inspected.",
				Required:    true,
			},
			"delete": {
				Type:        framework.TypeBool,
				Description: "Delete the keys instead of only listing them.",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathSweepRun},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSweepRun},
		},
		HelpSynopsis: "Find keys this engine issued that no lease owns any more.",
		HelpDescription: `Selectel keys never expire on their own, so a revocation that never
completed leaves a working key behind. This lists every key on the role's service user whose name
this engine minted, and deletes them when asked. Keys not named by this engine are left alone.`,
	}
}

func (b *selectelBackend) pathSweepRun(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	existing, err := c.listCredentials(ctx, role.ServiceUserID)
	if err != nil {
		return nil, fmt.Errorf("could not list the s3 credentials: %w", err)
	}

	held, err := leasedAccessKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	remove := data.Get("delete").(bool)
	orphans := make([]string, 0)
	deleted := 0

	for _, cred := range existing {
		if !strings.HasPrefix(cred.Name, credentialNamePrefix) {
			continue
		}
		if _, ok := held[cred.AccessKey]; ok {
			continue
		}

		orphans = append(orphans, cred.AccessKey)
		if !remove {
			continue
		}
		if err := c.deleteCredential(ctx, role.ServiceUserID, cred.AccessKey); err != nil && !errors.Is(err, errCredentialNotFound) {
			return nil, fmt.Errorf("could not delete %s: %w", cred.AccessKey, err)
		}
		deleted++
	}

	return &logical.Response{
		Data: map[string]any{
			"orphans": orphans,
			"deleted": deleted,
		},
	}, nil
}

func leasedAccessKeys(ctx context.Context, s logical.Storage) (map[string]struct{}, error) {
	held := make(map[string]struct{})

	leases, err := s.List(ctx, "leases/")
	if err != nil {
		return held, nil
	}

	for _, lease := range leases {
		entry, err := s.Get(ctx, "leases/"+lease)
		if err != nil || entry == nil {
			continue
		}

		var stored struct {
			InternalData map[string]any `json:"internal_data"`
		}
		if err := entry.DecodeJSON(&stored); err != nil {
			continue
		}
		if key, ok := stored.InternalData["access_key"].(string); ok {
			held[key] = struct{}{}
		}
	}

	return held, nil
}
