package selectel

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRoot(b *selectelBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSelectel,
			OperationVerb:   "rotate",
			OperationSuffix: "root-credentials",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateRoot},
		},
		HelpSynopsis: "Replace the password the engine authenticates with.",
		HelpDescription: `Generates a new password for the configured service user, sets it in
Selectel and stores it. Nobody, including the operator who first configured the engine, knows the
password afterwards. Storage is written before Selectel so a failed rotation can be rolled back
rather than locking the engine out of its own account.`,
	}
}

func (b *selectelBackend) pathRotateRoot(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
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

	password, err := generatePassword()
	if err != nil {
		return nil, err
	}

	previous := config.Password
	config.Password = password
	if err := storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	if err := c.setServiceUserPassword(ctx, config.UserID, password); err != nil {
		config.Password = previous
		if restoreErr := storeConfig(ctx, req.Storage, config); restoreErr != nil {
			return nil, fmt.Errorf(
				"selectel refused the new password (%w) and the old one could not be put back (%w): "+
					"set a password for service user %s by hand and write it to config",
				err, restoreErr, config.UserID)
		}
		return nil, fmt.Errorf("could not set the new password: %w", err)
	}

	b.reset()
	return nil, nil
}

func (c *client) setServiceUserPassword(ctx context.Context, userID, password string) error {
	body := map[string]any{"password": password}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("/iam/v1/service_users/%s", userID), body, nil)
}
