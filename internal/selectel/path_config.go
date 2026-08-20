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
)

var errMissingConfig = errors.New("write config before asking for credentials")

type selectelConfig struct {
	AuthURL     string `json:"auth_url"`
	IAMURL      string `json:"iam_url"`
	AccountID   string `json:"account_id"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	ProjectName string `json:"project_name"`
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
				Description: "Selectel account number the service user belongs to.",
				Required:    true,
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Service user allowed to manage S3 credentials through the IAM API.",
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
			"project_name": {
				Type:        framework.TypeString,
				Description: "Project the service user authenticates into.",
				Required:    true,
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
			"account_id":   config.AccountID,
			"username":     config.Username,
			"project_name": config.ProjectName,
			"auth_url":     config.AuthURL,
			"iam_url":      config.IAMURL,
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
	if raw, ok := data.GetOk("username"); ok {
		config.Username = raw.(string)
	}
	if raw, ok := data.GetOk("password"); ok {
		config.Password = raw.(string)
	}
	if raw, ok := data.GetOk("project_name"); ok {
		config.ProjectName = raw.(string)
	}
	if raw, ok := data.GetOk("auth_url"); ok {
		config.AuthURL = raw.(string)
	}
	if raw, ok := data.GetOk("iam_url"); ok {
		config.IAMURL = raw.(string)
	}

	if config.AuthURL == "" {
		config.AuthURL = defaultAuthURL
	}
	if config.IAMURL == "" {
		config.IAMURL = defaultIAMURL
	}

	for field, value := range map[string]string{
		"account_id":   config.AccountID,
		"username":     config.Username,
		"password":     config.Password,
		"project_name": config.ProjectName,
	} {
		if value == "" {
			return logical.ErrorResponse("%s is required", field), nil
		}
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()
	return nil, nil
}

func (b *selectelBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}
