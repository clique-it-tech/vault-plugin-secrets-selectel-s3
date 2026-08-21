package selectel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	staticRoleStoragePrefix    = "static-role/"
	staticCredentialNamePrefix = "vault-static-"
)

type staticRole struct {
	ServiceUserID   string        `json:"service_user_id"`
	ServiceUserName string        `json:"service_user_name"`
	ProjectID       string        `json:"project_id"`
	Bucket          string        `json:"bucket"`
	AccessKey       string        `json:"access_key"`
	SecretKey       string        `json:"secret_key"`
	LastRotation    time.Time     `json:"last_rotation"`
	RotationPeriod  time.Duration `json:"rotation_period"`
}

// nextRotation reports when the engine will replace the key by itself. The zero
// time means never: a role without a rotation period changes only when asked.
func (r *staticRole) nextRotation() time.Time {
	if r.RotationPeriod <= 0 {
		return time.Time{}
	}
	return r.LastRotation.Add(r.RotationPeriod)
}

func staticRoleNotFound(name string) error {
	return fmt.Errorf("no static role named %q", name)
}

func pathStaticRoles(b *selectelBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "static-roles/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixSelectel,
				OperationVerb:   "list",
				OperationSuffix: "static-roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathStaticRolesList},
			},
			HelpSynopsis: "List the static roles.",
		},
		{
			Pattern: "static-roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixSelectel,
				OperationSuffix: "static-role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the static role.",
					Required:    true,
				},
				"project_id": {
					Type:        framework.TypeString,
					Description: "Project the service user belongs to.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Project id",
					},
				},
				"bucket": {
					Type:        framework.TypeString,
					Description: "Bucket the key may act on. Leave empty to grant nothing beyond what the bucket policy already says.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:  "Bucket",
						Value: "clq-backups",
					},
				},
				"rotation_period": {
					Type: framework.TypeDurationSecond,
					Description: "How often the engine replaces the key on its own. " +
						"Leave it out and the key changes only when rotate-role is called.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:     "Rotate every",
						EditType: "ttl",
					},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticRoleRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStaticRoleDelete},
			},
			ExistenceCheck: b.pathStaticRoleExistence,
			HelpSynopsis:   "Own one long-lived key instead of minting one per read.",
			HelpDescription: `A dynamic role hands out a new key on every read, which suits a consumer
that asks once per process. A consumer that re-reads on a timer — a CSI driver syncing a Kubernetes
secret, say — would mint hundreds of keys a day that way. A static role holds a single key for its
own service user, hands the same one to every reader, and replaces it only when rotate-role is
called.`,
		},
		{
			Pattern: "static-creds/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixSelectel,
				OperationVerb:   "read",
				OperationSuffix: "static-credentials",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the static role.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathStaticCredsRead},
			},
			HelpSynopsis:    "Read the key a static role currently holds.",
			HelpDescription: "Reading changes nothing: the same key comes back until it is rotated.",
		},
		{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixSelectel,
				OperationVerb:   "rotate",
				OperationSuffix: "static-role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the static role.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleRotate},
			},
			HelpSynopsis: "Replace the key a static role holds.",
			HelpDescription: `Mints a new key, stores it, and only then deletes the old one, so a
failure never leaves the role without a working key. Consumers pick the new key up the next time
they read.`,
		},
	}
}

func staticRoleStoragePath(name string) string {
	return staticRoleStoragePrefix + name
}

func getStaticRole(ctx context.Context, s logical.Storage, name string) (*staticRole, error) {
	entry, err := s.Get(ctx, staticRoleStoragePath(name))
	if err != nil || entry == nil {
		return nil, err
	}
	role := new(staticRole)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func storeStaticRole(ctx context.Context, s logical.Storage, name string, role *staticRole) error {
	entry, err := logical.StorageEntryJSON(staticRoleStoragePath(name), role)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *selectelBackend) pathStaticRoleExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := getStaticRole(ctx, req.Storage, data.Get("name").(string))
	return role != nil, err
}

func (b *selectelBackend) pathStaticRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, staticRoleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *selectelBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(staticRoleNotFound(name).Error()), nil
	}
	return &logical.Response{Data: map[string]any{
		"project_id":        role.ProjectID,
		"bucket":            role.Bucket,
		"service_user_id":   role.ServiceUserID,
		"service_user_name": role.ServiceUserName,
		"access_key":        role.AccessKey,
		"last_rotation":     role.LastRotation.Format(time.RFC3339),
		"rotation_period":   int64(role.RotationPeriod.Seconds()),
	}}, nil
}

func (b *selectelBackend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	existing, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	role := existing
	if role == nil {
		role = new(staticRole)
	}
	if projectID, ok := data.GetOk("project_id"); ok {
		role.ProjectID = projectID.(string)
	}
	if bucket, ok := data.GetOk("bucket"); ok {
		role.Bucket = bucket.(string)
	}
	if period, ok := data.GetOk("rotation_period"); ok {
		role.RotationPeriod = time.Duration(period.(int)) * time.Second
	}
	if role.ProjectID == "" {
		return logical.ErrorResponse("project_id is required"), nil
	}

	dynamic, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if dynamic != nil {
		return logical.ErrorResponse(
			"a dynamic role named %q already exists; pick another name so the two do not share a service user", name), nil
	}

	shadow := &selectelRole{
		ServiceUserID:   role.ServiceUserID,
		ServiceUserName: role.ServiceUserName,
		ProjectID:       role.ProjectID,
		Bucket:          role.Bucket,
	}
	if err := b.provisionRole(ctx, req.Storage, "static-"+name, shadow); err != nil {
		return nil, err
	}
	role.ServiceUserID = shadow.ServiceUserID
	role.ServiceUserName = shadow.ServiceUserName

	if role.AccessKey == "" {
		if err := b.mintStaticKey(ctx, req.Storage, name, role); err != nil {
			return nil, err
		}
		return nil, nil
	}

	return nil, storeStaticRole(ctx, req.Storage, name, role)
}

func (b *selectelBackend) pathStaticCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(staticRoleNotFound(name).Error()), nil
	}
	if role.AccessKey == "" {
		return logical.ErrorResponse("static role %q holds no key yet; rotate it", name), nil
	}
	out := map[string]any{
		"access_key":    role.AccessKey,
		"secret_key":    role.SecretKey,
		"last_rotation": role.LastRotation.Format(time.RFC3339),
	}
	if next := role.nextRotation(); !next.IsZero() {
		out["ttl"] = int64(max(0, int64(time.Until(next).Seconds())))
	}
	return &logical.Response{Data: out}, nil
}

func (b *selectelBackend) pathStaticRoleRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(staticRoleNotFound(name).Error()), nil
	}
	if err := b.rotateStaticRole(ctx, req.Storage, name, role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return nil, nil
}

// rotateDueStaticRoles is what makes a rotation period mean anything: Vault
// calls it on the active node about once a minute. A role that cannot be
// rotated is logged and skipped, so one broken role never stops the others.
func (b *selectelBackend) rotateDueStaticRoles(ctx context.Context, req *logical.Request) error {
	names, err := req.Storage.List(ctx, staticRoleStoragePrefix)
	if err != nil {
		return err
	}

	for _, name := range names {
		role, err := getStaticRole(ctx, req.Storage, name)
		if err != nil || role == nil {
			continue
		}
		next := role.nextRotation()
		if next.IsZero() || time.Now().Before(next) {
			continue
		}
		if err := b.rotateStaticRole(ctx, req.Storage, name, role); err != nil {
			b.Logger().Error("could not rotate static role", "role", name, "error", err)
		}
	}
	return nil
}

func (b *selectelBackend) rotateStaticRole(ctx context.Context, s logical.Storage, name string, role *staticRole) error {
	previous := role.AccessKey
	if err := b.mintStaticKey(ctx, s, name, role); err != nil {
		return err
	}
	if previous == "" {
		return nil
	}

	c, err := b.getClient(ctx, s)
	if err != nil {
		return err
	}
	if err := c.deleteCredential(ctx, role.ServiceUserID, previous); err != nil && !errors.Is(err, errCredentialNotFound) {
		return fmt.Errorf("the new key is in place, but the old one %s could not be deleted: %w", previous, err)
	}
	return nil
}

// mintStaticKey puts the new key in storage before anything else can fail, so a
// rotation that breaks halfway leaves the role holding a key that works rather
// than none at all.
func (b *selectelBackend) mintStaticKey(ctx context.Context, s logical.Storage, name string, role *staticRole) error {
	c, err := b.getClient(ctx, s)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return errMissingConfig
		}
		return err
	}

	created, err := c.createCredential(ctx, role.ServiceUserID, &credentialRequest{
		Name:      fmt.Sprintf("%s%s-%d", staticCredentialNamePrefix, name, time.Now().UnixNano()),
		ProjectID: role.ProjectID,
	})
	if err != nil {
		return fmt.Errorf("could not create the s3 credential: %w", err)
	}

	role.AccessKey = created.AccessKey
	role.SecretKey = created.SecretKey
	role.LastRotation = time.Now().UTC()
	return storeStaticRole(ctx, s, name, role)
}

func (b *selectelBackend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	shadow := &selectelRole{
		ServiceUserID:   role.ServiceUserID,
		ServiceUserName: role.ServiceUserName,
		ProjectID:       role.ProjectID,
		Bucket:          role.Bucket,
	}
	if err := b.deprovisionRole(ctx, req.Storage, shadow); err != nil {
		return nil, err
	}
	return nil, req.Storage.Delete(ctx, staticRoleStoragePath(name))
}
