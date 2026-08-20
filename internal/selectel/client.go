package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	errBackendNotConfigured = errors.New("selectel backend is not configured")
	errCredentialNotFound   = errors.New("s3 credential no longer exists")
)

const (
	tokenHeader     = "X-Auth-Token"
	subjectHeader   = "X-Subject-Token"
	tokenEarlyRenew = 5 * time.Minute
	requestTimeout  = 30 * time.Second
)

type client struct {
	http    *http.Client
	authURL string
	iamURL  string

	account  string
	username string
	password string
	project  string

	lock      sync.Mutex
	token     string
	tokenTill time.Time
}

func newClient(c *selectelConfig) *client {
	return &client{
		http:     &http.Client{Timeout: requestTimeout},
		authURL:  strings.TrimSuffix(c.AuthURL, "/"),
		iamURL:   strings.TrimSuffix(c.IAMURL, "/"),
		account:  c.AccountID,
		username: c.Username,
		password: c.Password,
		project:  c.ProjectName,
	}
}

type credential struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Name      string `json:"name"`
	ProjectID string `json:"project_id"`
}

type credentialList struct {
	Credentials []credential `json:"credentials"`
}

type credentialRequest struct {
	Name      string `json:"name"`
	ProjectID string `json:"project_id"`
}

func (c *client) authenticate(ctx context.Context) (string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.token != "" && time.Now().Add(tokenEarlyRenew).Before(c.tokenTill) {
		return c.token, nil
	}

	body := map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"password"},
				"password": map[string]any{
					"user": map[string]any{
						"name":     c.username,
						"domain":   map[string]string{"name": c.account},
						"password": c.password,
					},
				},
			},
			"scope": map[string]any{
				"project": map[string]any{
					"name":   c.project,
					"domain": map[string]string{"name": c.account},
				},
			},
		},
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authURL+"/auth/tokens", bytes.NewReader(encoded))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("selectel refused the service user: %d %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	token := resp.Header.Get(subjectHeader)
	if token == "" {
		return "", errors.New("selectel returned no token")
	}

	var issued struct {
		Token struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return "", err
	}

	c.token = token
	c.tokenTill = issued.Token.ExpiresAt
	return token, nil
}

func (c *client) do(ctx context.Context, method, path string, body any, out any) error {
	token, err := c.authenticate(ctx)
	if err != nil {
		return err
	}

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.iamURL+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set(tokenHeader, token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return errCredentialNotFound
	}
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("selectel returned %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) createCredential(ctx context.Context, userID string, req *credentialRequest) (*credential, error) {
	out := new(credential)
	path := fmt.Sprintf("/iam/v1/service_users/%s/credentials", userID)
	if err := c.do(ctx, http.MethodPost, path, req, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *client) deleteCredential(ctx context.Context, userID, accessKey string) error {
	path := fmt.Sprintf("/iam/v1/service_users/%s/credentials/%s", userID, accessKey)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

func (c *client) listCredentials(ctx context.Context, userID string) ([]credential, error) {
	out := new(credentialList)
	path := fmt.Sprintf("/iam/v1/service_users/%s/credentials", userID)
	if err := c.do(ctx, http.MethodGet, path, nil, out); err != nil {
		return nil, err
	}
	return out.Credentials, nil
}
