package selectel

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Delete what is found",
				},
			},
			"older_than": {
				Type: framework.TypeDurationSecond,
				Description: "Only consider keys minted longer ago than this. " +
					"Defaults to the role's max_ttl, which is the longest a lease can hold a key.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:     "Older than",
					EditType: "ttl",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathSweepRun},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSweepRun},
		},
		HelpSynopsis: "Find keys this engine issued that no lease can still own.",
		HelpDescription: `Selectel keys never expire on their own, so a revocation that never
completed leaves a working key behind. A lease cannot outlive the role's max_ttl, so any key this
engine minted longer ago than that and which Selectel still lists has outlived every lease that
could have owned it. Keys younger than that may still be in use and are never touched, and keys
this engine did not mint are left alone.`,
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

	age := role.MaxTTL
	if raw, ok := data.GetOk("older_than"); ok {
		age = time.Duration(raw.(int)) * time.Second
	}
	if age <= 0 {
		return logical.ErrorResponse("older_than must be positive; the role has no max_ttl to fall back on"), nil
	}
	cutoff := time.Now().Add(-age)

	remove := data.Get("delete").(bool)
	orphans := make([]string, 0)
	skipped := 0
	deleted := 0

	for _, cred := range existing {
		mintedAt, ok := mintedAt(cred.Name)
		if !ok {
			continue
		}
		if mintedAt.After(cutoff) {
			skipped++
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
			"orphans":     orphans,
			"deleted":     deleted,
			"still_young": skipped,
			"older_than":  int(age.Seconds()),
		},
	}, nil
}

func mintedAt(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, credentialNamePrefix) {
		return time.Time{}, false
	}
	// A static role's key is meant to outlive any lease, so age says nothing
	// about whether it is still in use.
	if strings.HasPrefix(name, staticCredentialNamePrefix) {
		return time.Time{}, false
	}
	at := strings.LastIndex(name, "-")
	if at < 0 {
		return time.Time{}, false
	}
	nanos, err := strconv.ParseInt(name[at+1:], 10, 64)
	if err != nil || nanos <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, nanos), true
}
