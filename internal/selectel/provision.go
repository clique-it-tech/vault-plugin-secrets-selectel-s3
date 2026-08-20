package selectel

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleS3User      = "s3.user"
	roleS3Admin     = "s3.admin"
	adminNamePrefix = "vault-policy-admin-"
)

type serviceUserRole struct {
	RoleName  string `json:"role_name"`
	Scope     string `json:"scope"`
	ProjectID string `json:"project_id"`
}

type serviceUserRequest struct {
	Name     string            `json:"name"`
	Password string            `json:"password"`
	Enabled  bool              `json:"enabled"`
	Roles    []serviceUserRole `json:"roles"`
}

type serviceUser struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Enabled bool              `json:"enabled"`
	Roles   []serviceUserRole `json:"roles"`
}

type serviceUserList struct {
	Users []serviceUser `json:"users"`
}

func (c *client) listServiceUsers(ctx context.Context) ([]serviceUser, error) {
	out := new(serviceUserList)
	if err := c.do(ctx, http.MethodGet, "/iam/v1/service_users", nil, out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

func (c *client) findServiceUser(ctx context.Context, name string) (*serviceUser, error) {
	users, err := c.listServiceUsers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Name == name {
			return &users[i], nil
		}
	}
	return nil, nil
}

func (c *client) createServiceUser(ctx context.Context, name, roleName, projectID string) (*serviceUser, error) {
	password, err := generatePassword()
	if err != nil {
		return nil, err
	}

	out := new(serviceUser)
	req := &serviceUserRequest{
		Name:     name,
		Password: password,
		Enabled:  true,
		Roles:    []serviceUserRole{{RoleName: roleName, Scope: "project", ProjectID: projectID}},
	}
	if err := c.do(ctx, http.MethodPost, "/iam/v1/service_users", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *client) deleteServiceUser(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/iam/v1/service_users/%s", id), nil, nil)
}

// withS3Admin runs fn with a service user that exists only for the duration of
// the call. Selectel refuses PutBucketPolicy to anything less than s3.admin, and
// leaving that role on the engine's own account would mean the credential in the
// cluster could rewrite every bucket. Creating and destroying it per operation
// keeps that power alive for seconds rather than forever.
func (c *client) withS3Admin(ctx context.Context, projectID, endpoint, region string, fn func(*s3Client) error) (err error) {
	name := fmt.Sprintf("%s%d", adminNamePrefix, time.Now().UnixNano())

	admin, err := c.createServiceUser(ctx, name, roleS3Admin, projectID)
	if err != nil {
		return fmt.Errorf("could not create the temporary policy admin: %w", err)
	}

	defer func() {
		if removeErr := c.deleteServiceUser(ctx, admin.ID); removeErr != nil && !errors.Is(removeErr, errCredentialNotFound) {
			err = errors.Join(err, fmt.Errorf("could not remove the temporary policy admin %s: %w", admin.ID, removeErr))
		}
	}()

	cred, err := c.createCredential(ctx, admin.ID, &credentialRequest{Name: "policy-write", ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("could not issue a key for the temporary policy admin: %w", err)
	}

	return fn(newS3Client(endpoint, region, cred.AccessKey, cred.SecretKey))
}

const (
	lowers         = "abcdefghijklmnopqrstuvwxyz"
	uppers         = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits         = "0123456789"
	symbols        = "!@#$%^&*-_"
	alphabet       = lowers + uppers + digits + symbols
	passwordLength = 24
)

// generatePassword satisfies Selectel's complexity rule, which rejects anything
// without all four character classes with insecure_password.
func generatePassword() (string, error) {
	out := make([]byte, 0, passwordLength)
	for _, class := range []string{lowers, uppers, digits, symbols} {
		c, err := pick(class)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for len(out) < passwordLength {
		c, err := pick(alphabet)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}

	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

func pick(class string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(class))))
	if err != nil {
		return 0, err
	}
	return class[n.Int64()], nil
}

func serviceUserNameFor(role string) string {
	return "s3-" + role
}

// provisionRole brings Selectel in line with the role that was just written:
// the service user exists, and the bucket policy names it. Both steps are
// idempotent, so rewriting an unchanged role costs two reads and no writes.
func (b *selectelBackend) provisionRole(ctx context.Context, s logical.Storage, name string, role *selectelRole) error {
	c, err := b.getClient(ctx, s)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return errMissingConfig
		}
		return err
	}

	if role.ServiceUserID == "" {
		role.ServiceUserName = serviceUserNameFor(name)

		found, err := c.findServiceUser(ctx, role.ServiceUserName)
		if err != nil {
			return fmt.Errorf("could not look for the service user: %w", err)
		}
		if found == nil {
			found, err = c.createServiceUser(ctx, role.ServiceUserName, roleS3User, role.ProjectID)
			if err != nil {
				return fmt.Errorf("could not create the service user: %w", err)
			}
		}
		role.ServiceUserID = found.ID
	}

	if role.Bucket == "" {
		return nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return err
	}

	policy, err := b.readBucketPolicyForRole(ctx, s, c, role, config)
	if err != nil {
		return err
	}
	if !grantBucketAccess(policy, role.Bucket, role.ServiceUserID) {
		return nil
	}

	return c.withS3Admin(ctx, role.ProjectID, config.S3Endpoint, config.S3Region, func(s3 *s3Client) error {
		if err := s3.putBucketPolicy(ctx, role.Bucket, policy); err != nil {
			return fmt.Errorf("could not update the policy of %s: %w", role.Bucket, err)
		}
		return nil
	})
}

// readBucketPolicyForRole reads the policy through whichever service user the
// policy already names. A role's own user works once it has been granted, but a
// brand new one has not been yet, so the engine falls back to a sibling role
// bound to the same bucket. Only the very first role on a bucket has nobody to
// borrow from, and that one needs an operator.
func (b *selectelBackend) readBucketPolicyForRole(ctx context.Context, s logical.Storage, c *client, role *selectelRole, config *selectelConfig) (*bucketPolicy, error) {
	policy, err := c.readBucketPolicy(ctx, role, config)
	if err == nil {
		return policy, nil
	}
	first := err

	names, listErr := s.List(ctx, rolesStoragePrefix)
	if listErr != nil {
		return nil, first
	}

	for _, name := range names {
		sibling, getErr := getRole(ctx, s, name)
		if getErr != nil || sibling == nil {
			continue
		}
		if sibling.Bucket != role.Bucket || sibling.ServiceUserID == role.ServiceUserID || sibling.ServiceUserID == "" {
			continue
		}
		if policy, err := c.readBucketPolicy(ctx, sibling, config); err == nil {
			return policy, nil
		}
	}

	return nil, first
}

// readBucketPolicy reads through a key of the given role's service user. Selectel
// lets s3.admin write a bucket policy but not read one, so the only identity
// that can see the current policy is a principal the policy already names. That
// makes the first grant on a bucket an operator's job; afterwards the engine
// names itself and can keep the policy up to date on its own.
func (c *client) readBucketPolicy(ctx context.Context, role *selectelRole, config *selectelConfig) (*bucketPolicy, error) {
	cred, err := c.createCredential(ctx, role.ServiceUserID, &credentialRequest{
		Name:      fmt.Sprintf("policy-read-%d", time.Now().UnixNano()),
		ProjectID: role.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not issue a key to read the policy: %w", err)
	}
	defer func() {
		_ = c.deleteCredential(ctx, role.ServiceUserID, cred.AccessKey)
	}()

	s3 := newS3Client(config.S3Endpoint, config.S3Region, cred.AccessKey, cred.SecretKey)
	policy, err := s3.getBucketPolicy(ctx, role.Bucket)
	if err != nil {
		return nil, fmt.Errorf(
			"could not read the policy of %s: %w. Selectel only shows a bucket policy to a principal it already names, "+
				"so grant %s s3:GetBucketPolicy on that bucket once, then this role manages itself",
			role.Bucket, err, role.ServiceUserID)
	}
	return policy, nil
}

// deprovisionRole undoes provisionRole. The service user is removed last,
// which also drops any key still attached to it.
func (b *selectelBackend) deprovisionRole(ctx context.Context, s logical.Storage, role *selectelRole) error {
	c, err := b.getClient(ctx, s)
	if err != nil {
		if errors.Is(err, errBackendNotConfigured) {
			return nil
		}
		return err
	}

	if role.Bucket != "" {
		config, err := getConfig(ctx, s)
		if err != nil {
			return err
		}

		policy, err := b.readBucketPolicyForRole(ctx, s, c, role, config)
		if err != nil {
			return err
		}
		if revokeBucketAccess(policy, role.ServiceUserID) {
			err = c.withS3Admin(ctx, role.ProjectID, config.S3Endpoint, config.S3Region, func(s3 *s3Client) error {
				return s3.putBucketPolicy(ctx, role.Bucket, policy)
			})
		}
		if err != nil {
			return fmt.Errorf("could not take %s out of the policy of %s: %w", role.ServiceUserID, role.Bucket, err)
		}
	}

	if role.ServiceUserName == "" {
		return nil
	}
	if err := c.deleteServiceUser(ctx, role.ServiceUserID); err != nil && !errors.Is(err, errCredentialNotFound) {
		return fmt.Errorf("could not remove the service user: %w", err)
	}
	return nil
}
