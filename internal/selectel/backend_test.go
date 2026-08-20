package selectel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type fakeSelectel struct {
	server *httptest.Server

	lock        sync.Mutex
	credentials map[string]credential
	deleted     []string
	issued      int
}

func newFakeSelectel(t *testing.T) *fakeSelectel {
	t.Helper()

	f := &fakeSelectel{credentials: map[string]credential{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/identity/v3/auth/tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(subjectHeader, "token-for-tests")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{"expires_at": time.Now().Add(time.Hour)},
		})
	})
	mux.HandleFunc("/iam/v1/service_users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(tokenHeader) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		f.lock.Lock()
		defer f.lock.Unlock()

		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.Method == http.MethodPost:
			f.issued++
			var body credentialRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			cred := credential{
				AccessKey: "AK" + body.Name,
				SecretKey: "SK" + body.Name,
				Name:      body.Name,
				ProjectID: body.ProjectID,
			}
			f.credentials[cred.AccessKey] = cred
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(cred)
		case r.Method == http.MethodGet:
			list := credentialList{}
			for _, cred := range f.credentials {
				list.Credentials = append(list.Credentials, cred)
			}
			_ = json.NewEncoder(w).Encode(list)
		case r.Method == http.MethodDelete:
			key := parts[len(parts)-1]
			if _, ok := f.credentials[key]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(f.credentials, key)
			f.deleted = append(f.deleted, key)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func testBackend(t *testing.T, fake *fakeSelectel) (logical.Backend, logical.Storage) {
	t.Helper()

	storage := &logical.InmemStorage{}
	b, err := Factory(context.Background(), &logical.BackendConfig{
		StorageView: storage,
		Logger:      nil,
		System:      &logical.StaticSystemView{DefaultLeaseTTLVal: time.Hour, MaxLeaseTTLVal: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("could not build the backend: %v", err)
	}

	write(t, b, storage, "config", map[string]any{
		"account_id": "123456",
		"user_id":    "user-stronghold",
		"password":   "secret",

		"auth_url": fake.server.URL + "/identity/v3",
		"iam_url":  fake.server.URL,
	})

	return b, storage
}

func write(t *testing.T, b logical.Backend, s logical.Storage, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}
	return resp
}

func read(t *testing.T, b logical.Backend, s logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("%s failed: %v", path, err)
	}
	return resp
}

func TestCredentialsFollowTheRole(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{
		"service_user_id": "user-1",
		"project_id":      "project-1",
		"ttl":             600,
	})

	resp := read(t, b, s, "creds/storage")
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected a leased secret")
	}
	if resp.Data["access_key"] == "" || resp.Data["secret_key"] == "" {
		t.Fatal("expected both halves of the key")
	}
	if resp.Secret.TTL != 10*time.Minute {
		t.Fatalf("expected the role ttl, got %s", resp.Secret.TTL)
	}
	if resp.Secret.InternalData["service_user_id"] != "user-1" {
		t.Fatal("the lease must remember which user to clean up")
	}
}

func TestUnknownRoleIsRefused(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	resp := read(t, b, s, "creds/missing")
	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error for an unknown role")
	}
	if fake.issued != 0 {
		t.Fatal("nothing should have been created")
	}
}

func TestRevokeDeletesTheKey(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{
		"service_user_id": "user-1",
		"project_id":      "project-1",
	})

	issued := read(t, b, s, "creds/storage")
	accessKey := issued.Secret.InternalData["access_key"].(string)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/storage",
		Storage:   s,
		Secret:    issued.Secret,
	})
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	fake.lock.Lock()
	defer fake.lock.Unlock()
	if len(fake.deleted) != 1 || fake.deleted[0] != accessKey {
		t.Fatalf("expected %s to be deleted, got %v", accessKey, fake.deleted)
	}
}

func TestRevokeToleratesAKeyThatIsAlreadyGone(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{
		"service_user_id": "user-1",
		"project_id":      "project-1",
	})
	issued := read(t, b, s, "creds/storage")

	fake.lock.Lock()
	fake.credentials = map[string]credential{}
	fake.lock.Unlock()

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/storage",
		Storage:   s,
		Secret:    issued.Secret,
	}); err != nil {
		t.Fatalf("revoke should not fail when the key is already gone: %v", err)
	}
}

func TestSweepReportsOrphansAndLeavesForeignKeys(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{
		"service_user_id": "user-1",
		"project_id":      "project-1",
	})
	read(t, b, s, "creds/storage")

	fake.lock.Lock()
	fake.credentials["AKmanual"] = credential{AccessKey: "AKmanual", Name: "made-by-hand"}
	fake.lock.Unlock()

	resp := read(t, b, s, "sweep/storage")
	orphans := resp.Data["orphans"].([]string)
	if len(orphans) != 1 || !strings.HasPrefix(orphans[0], "AK"+credentialNamePrefix) {
		t.Fatalf("expected only the vault key to be reported, got %v", orphans)
	}
	if resp.Data["deleted"].(int) != 0 {
		t.Fatal("a plain read must not delete anything")
	}

	write(t, b, s, "sweep/storage", map[string]any{"delete": true})

	fake.lock.Lock()
	defer fake.lock.Unlock()
	if _, ok := fake.credentials["AKmanual"]; !ok {
		t.Fatal("a key this engine did not issue must survive the sweep")
	}
	if len(fake.credentials) != 1 {
		t.Fatalf("expected the orphan to be gone, left with %v", fake.credentials)
	}
}

func TestRoleRejectsTtlAboveMaxTtl(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	resp := write(t, b, s, "roles/bad", map[string]any{
		"service_user_id": "user-1",
		"project_id":      "project-1",
		"ttl":             3600,
		"max_ttl":         600,
	})
	if resp == nil || !resp.IsError() {
		t.Fatal("expected the role to be refused")
	}
}

func TestConfigNeverReturnsThePassword(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	resp := read(t, b, s, "config")
	if _, leaked := resp.Data["password"]; leaked {
		t.Fatal("the password must never be readable")
	}
}
