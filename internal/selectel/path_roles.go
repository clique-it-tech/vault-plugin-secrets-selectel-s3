package selectel

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const rolesStoragePrefix = "roles/"

type selectelRole struct {
	ServiceUserID   string        `json:"service_user_id"`
	ServiceUserName string        `json:"service_user_name"`
	ProjectID       string        `json:"project_id"`
	Bucket          string        `json:"bucket"`
	TTL             time.Duration `json:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
}

func roleNotFound(name string) error {
	return fmt.Errorf("no role named %q", name)
}

func pathRoles(b *selectelBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixSelectel,
				OperationSuffix: "role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"service_user_id": {
					Type:        framework.TypeString,
					Description: "Existing service user to bind to. Leave it out and the engine creates one named after the role.",
				},
				"bucket": {
					Type:        framework.TypeString,
					Description: "Bucket this role may reach. Writing the role adds its service user to that bucket's policy; deleting the role takes it back out.",
				},
				"project_id": {
					Type:        framework.TypeString,
					Description: "Project the credential is created in.",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "How long an issued key stays valid before Vault deletes it.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Ceiling for renewals of an issued key.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
			},
			ExistenceCheck:  b.pathRolesExistence,
			HelpSynopsis:    "Bind a role to one Selectel service user.",
			HelpDescription: "A policy that names one role cannot reach another service user, and therefore cannot reach another bucket.",
		},
		{
			Pattern: "roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixSelectel,
				OperationSuffix: "roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
			},
			HelpSynopsis: "List the roles this engine knows.",
		},
	}
}

func getRole(ctx context.Context, s logical.Storage, name string) (*selectelRole, error) {
	entry, err := s.Get(ctx, rolesStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := new(selectelRole)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func (b *selectelBackend) pathRolesExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *selectelBackend) pathRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"service_user_id":   role.ServiceUserID,
			"service_user_name": role.ServiceUserName,
			"project_id":        role.ProjectID,
			"bucket":            role.Bucket,
			"ttl":               int64(role.TTL.Seconds()),
			"max_ttl":           int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *selectelBackend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(selectelRole)
	}

	if raw, ok := data.GetOk("service_user_id"); ok {
		role.ServiceUserID = raw.(string)
	}
	if raw, ok := data.GetOk("project_id"); ok {
		role.ProjectID = raw.(string)
	}
	if raw, ok := data.GetOk("bucket"); ok {
		role.Bucket = raw.(string)
	}
	if raw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(raw.(int)) * time.Second
	}

	if role.ProjectID == "" {
		return logical.ErrorResponse("project_id is required"), nil
	}
	if err := b.provisionRole(ctx, req.Storage, name, role); err != nil {
		return nil, err
	}
	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be longer than max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *selectelBackend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role != nil {
		if err := b.deprovisionRole(ctx, req.Storage, role); err != nil {
			return nil, err
		}
	}

	if err := req.Storage.Delete(ctx, rolesStoragePrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *selectelBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, rolesStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
