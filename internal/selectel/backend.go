package selectel

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixSelectel = "selectel"
	secretTypeS3Credential  = "selectel_s3_credential"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type selectelBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *client
}

func backend() *selectelBackend {
	b := &selectelBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath, rolesStoragePrefix + "*"},
		},
		Paths: framework.PathAppend(
			pathRoles(b),
			[]*framework.Path{
				pathConfig(b),
				pathRotateRoot(b),
				pathAdoptBucket(b),
				pathDropStatement(b),
				pathCredentials(b),
				pathSweep(b),
			},
		),
		Secrets: []*framework.Secret{
			b.s3Credential(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return b
}

func (b *selectelBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

func (b *selectelBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *selectelBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	b.client = newClient(config)
	return b.client, nil
}

const backendHelp = `
The Selectel secrets engine issues S3 access keys on demand. Every key belongs
to a Vault lease and is deleted from Selectel when that lease ends. Selectel
keys carry no expiry of their own, so the lease is the only thing that stops a
leaked key: keep TTLs short, and sweep the account periodically to catch keys
whose revocation never completed.
`
