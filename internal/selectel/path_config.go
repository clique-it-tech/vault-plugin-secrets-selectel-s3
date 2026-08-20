package selectel

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
	defaultAuthURL    = "https://cloud.api.selcloud.ru/identity/v3"
	defaultIAMURL     = "https://api.selectel.ru"
	defaultS3Endpoint = "https://s3.ru-7.storage.selcloud.ru"
	defaultS3Region   = "ru-7"
)

var errMissingConfig = errors.New("write config before asking for credentials")

type selectelConfig struct {
	AuthURL   string `json:"auth_url"`
	IAMURL    string `json:"iam_url"`
	AccountID string `json:"account_id"`
	UserID    string `json:"user_id"`
	Password  string `json:"password"`

	S3Endpoint string `json:"s3_endpoint"`
	S3Region   string `json:"s3_region"`
}

func pathConfig(b *selectelBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSelectel,
		},
		Fields: map[string]*framework.FieldSchema{
			"account_id": {
				Type:        framework.TypeString,
				Description: "Selectel account number. The engine asks for a token scoped to this account, which is where the iam.admin role lives.",
				Required:    true,
			},
			"user_id": {
				Type:        framework.TypeString,
				Description: "Id of the service user allowed to manage S3 credentials through the IAM API.",
				Required:    true,
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password of that service user.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"auth_url": {
				Type:        framework.TypeString,
				Description: "Keystone endpoint that issues IAM tokens.",
				Default:     defaultAuthURL,
			},
			"iam_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the Selectel IAM API.",
				Default:     defaultIAMURL,
			},
			"s3_endpoint": {
				Type:        framework.TypeString,
				Description: "Object storage endpoint, used when a role manages a bucket policy.",
				Default:     defaultS3Endpoint,
			},
			"s3_region": {
				Type:        framework.TypeString,
				Description: "Region the object storage endpoint belongs to.",
				Default:     defaultS3Region,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistence,
		HelpSynopsis:    "Configure the Selectel account this engine talks to.",
		HelpDescription: "The password is never returned once written.",
	}
}

func getConfig(ctx context.Context, s logical.Storage) (*selectelConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(selectelConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *selectelBackend) pathConfigExistence(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (bool, error) {
	return false, nil
}

func (b *selectelBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"account_id":  config.AccountID,
			"user_id":     config.UserID,
			"auth_url":    config.AuthURL,
			"iam_url":     config.IAMURL,
			"s3_endpoint": config.S3Endpoint,
			"s3_region":   config.S3Region,
		},
	}, nil
}

func (b *selectelBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(selectelConfig)
	}

	if raw, ok := data.GetOk("account_id"); ok {
		config.AccountID = raw.(string)
	}
	if raw, ok := data.GetOk("user_id"); ok {
		config.UserID = raw.(string)
	}
	if raw, ok := data.GetOk("password"); ok {
		config.Password = raw.(string)
	}
	if raw, ok := data.GetOk("auth_url"); ok {
		config.AuthURL = raw.(string)
	}
	if raw, ok := data.GetOk("iam_url"); ok {
		config.IAMURL = raw.(string)
	}
	if raw, ok := data.GetOk("s3_endpoint"); ok {
		config.S3Endpoint = raw.(string)
	}
	if raw, ok := data.GetOk("s3_region"); ok {
		config.S3Region = raw.(string)
	}

	if config.AuthURL == "" {
		config.AuthURL = defaultAuthURL
	}
	if config.IAMURL == "" {
		config.IAMURL = defaultIAMURL
	}
	if config.S3Endpoint == "" {
		config.S3Endpoint = defaultS3Endpoint
	}
	if config.S3Region == "" {
		config.S3Region = defaultS3Region
	}

	for field, value := range map[string]string{
		"account_id": config.AccountID,
		"user_id":    config.UserID,
		"password":   config.Password,
	} {
		if value == "" {
			return logical.ErrorResponse("%s is required", field), nil
		}
	}

	if err := storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	b.reset()
	return nil, nil
}

func storeConfig(ctx context.Context, s logical.Storage, config *selectelConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *selectelBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}
