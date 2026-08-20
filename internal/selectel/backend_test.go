package selectel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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
	users       map[string]serviceUser
	policies    map[string]string
	readableBy  map[string]struct{}
	keyOwners   map[string]string
	deleted     []string
	created     []string
	removed     []string
	issued      int
}

func newFakeSelectel(t *testing.T) *fakeSelectel {
	t.Helper()

	f := &fakeSelectel{
		credentials: map[string]credential{},
		users:       map[string]serviceUser{},
		policies:    map[string]string{},
		keyOwners:   map[string]string{},
	}

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
		if !strings.Contains(r.URL.Path, "/credentials") {
			if r.Method != http.MethodDelete {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			id := parts[len(parts)-1]
			if _, ok := f.users[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(f.users, id)
			f.removed = append(f.removed, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}

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
			f.keyOwners[cred.AccessKey] = parts[len(parts)-2]
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

	mux.HandleFunc("/iam/v1/service_users", func(w http.ResponseWriter, r *http.Request) {
		f.lock.Lock()
		defer f.lock.Unlock()

		switch r.Method {
		case http.MethodPost:
			var body serviceUserRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Password == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			user := serviceUser{ID: "id-" + body.Name, Name: body.Name, Enabled: true, Roles: body.Roles}
			f.users[user.ID] = user
			f.created = append(f.created, body.Name)
			_ = json.NewEncoder(w).Encode(user)
		case http.MethodGet:
			list := serviceUserList{}
			for _, u := range f.users {
				list.Users = append(list.Users, u)
			}
			_ = json.NewEncoder(w).Encode(list)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.lock.Lock()
		defer f.lock.Unlock()

		trimmed := strings.Trim(r.URL.Path, "/")
		if strings.HasPrefix(trimmed, "iam/v1/service_users/") && r.Method == http.MethodDelete {
			id := strings.TrimPrefix(trimmed, "iam/v1/service_users/")
			if _, ok := f.users[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(f.users, id)
			f.removed = append(f.removed, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.URL.Query().Has("policy") {
			switch r.Method {
			case http.MethodGet:
				if f.readableBy != nil {
					if _, allowed := f.readableBy[f.keyOwner(r.Header.Get("Authorization"))]; !allowed {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
				stored, ok := f.policies[trimmed]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte(stored))
			case http.MethodPut:
				body, _ := io.ReadAll(r.Body)
				f.policies[trimmed] = string(body)
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// keyOwner maps a signed request back to the service user whose key signed it,
// so the fake can refuse a read the way Selectel refuses one from a principal
// the policy does not name.
func (f *fakeSelectel) keyOwner(authorization string) string {
	for accessKey, owner := range f.keyOwners {
		if strings.Contains(authorization, accessKey) {
			return owner
		}
	}
	return ""
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

		"auth_url":    fake.server.URL + "/identity/v3",
		"iam_url":     fake.server.URL,
		"s3_endpoint": fake.server.URL,
		"s3_region":   "ru-7",
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

func policyOf(t *testing.T, fake *fakeSelectel, bucket string) *bucketPolicy {
	t.Helper()
	fake.lock.Lock()
	defer fake.lock.Unlock()

	stored, ok := fake.policies[bucket]
	if !ok {
		t.Fatalf("bucket %s has no policy", bucket)
	}
	policy := new(bucketPolicy)
	if err := json.Unmarshal([]byte(stored), policy); err != nil {
		t.Fatalf("stored policy is not json: %v", err)
	}
	return policy
}

func TestWritingARoleCreatesItsServiceUser(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{"project_id": "project-1"})

	resp := read(t, b, s, "roles/storage")
	if resp.Data["service_user_name"] != "s3-storage" {
		t.Fatalf("expected the user to be named after the role, got %v", resp.Data["service_user_name"])
	}
	if resp.Data["service_user_id"] != "id-s3-storage" {
		t.Fatalf("expected the created id to be remembered, got %v", resp.Data["service_user_id"])
	}

	fake.lock.Lock()
	defer fake.lock.Unlock()
	if !slices.Contains(fake.created, "s3-storage") {
		t.Fatalf("expected s3-storage to be created, got %v", fake.created)
	}
}

func TestWritingARoleGrantsTheBucketAndCleansUpTheAdmin(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{"project_id": "project-1", "bucket": "aether"})

	policy := policyOf(t, fake, "aether")
	if statementAt(policy, vaultStatementID) < 0 || statementAt(policy, readerStatementID) < 0 {
		t.Fatalf("expected the consumer and reader statements, got %+v", policy.Statement)
	}
	if got := principals(policy.Statement[statementAt(policy, vaultStatementID)]); !slices.Contains(got, "id-s3-storage") {
		t.Fatalf("expected the service user in the policy, got %v", got)
	}

	fake.lock.Lock()
	defer fake.lock.Unlock()
	for _, name := range fake.created {
		if strings.HasPrefix(name, adminNamePrefix) {
			if !slices.Contains(fake.removed, "id-"+name) {
				t.Fatalf("the temporary admin %s outlived the operation", name)
			}
		}
	}
	if len(fake.users) != 2 {
		t.Fatalf("expected the role's user and the reader to remain, got %v", fake.users)
	}
}

func TestWritingARoleKeepsForeignStatements(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	fake.lock.Lock()
	fake.policies["aether"] = `{"Version":"2012-10-17","Statement":[{"Sid":"allow-read-object","Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::aether/*"]}]}`
	fake.lock.Unlock()

	write(t, b, s, "roles/storage", map[string]any{"project_id": "project-1", "bucket": "aether"})

	policy := policyOf(t, fake, "aether")
	if len(policy.Statement) != 3 {
		t.Fatalf("expected the existing statement to survive alongside both of ours, got %+v", policy.Statement)
	}
	if policy.Statement[0].Sid != "allow-read-object" {
		t.Fatal("the public read rule must stay first and intact")
	}
}

func TestRewritingARoleChangesNothing(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{"project_id": "project-1", "bucket": "aether"})
	first := policyOf(t, fake, "aether")

	write(t, b, s, "roles/storage", map[string]any{"project_id": "project-1", "bucket": "aether"})
	second := policyOf(t, fake, "aether")

	if len(first.Statement) != len(second.Statement) {
		t.Fatal("rewriting the role must not add a second statement")
	}
	if got := principals(second.Statement[0]); len(got) != 1 {
		t.Fatalf("the principal must not be duplicated, got %v", got)
	}
}

func TestDeletingARoleTakesTheUserBackOut(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/storage", map[string]any{"project_id": "project-1", "bucket": "aether"})

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/storage",
		Storage:   s,
	}); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	policy := policyOf(t, fake, "aether")
	if statementAt(policy, vaultStatementID) >= 0 {
		t.Fatalf("the empty consumer statement should be gone, got %+v", policy.Statement)
	}
	if statementAt(policy, readerStatementID) < 0 {
		t.Fatal("the reader belongs to the engine and must outlive one role")
	}

	fake.lock.Lock()
	defer fake.lock.Unlock()
	if _, alive := fake.users["id-s3-storage"]; alive {
		t.Fatal("the service user should have been removed with the role")
	}
}

func TestTheEngineKeepsItsOwnPolicyReader(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/first", map[string]any{"project_id": "project-1", "bucket": "aether"})

	policy := policyOf(t, fake, "aether")
	at := statementAt(policy, readerStatementID)
	if at < 0 {
		t.Fatalf("expected a statement for the reader, got %+v", policy.Statement)
	}
	if got := principals(policy.Statement[at]); !slices.Contains(got, "id-"+policyReaderName) {
		t.Fatalf("expected the reader in its own statement, got %v", got)
	}
	action := policy.Statement[at].Action.([]any)
	if len(action) != 1 || action[0] != "s3:GetBucketPolicy" {
		t.Fatalf("the reader must be granted nothing but the read, got %v", action)
	}

	fake.lock.Lock()
	fake.readableBy = map[string]struct{}{"id-" + policyReaderName: {}}
	fake.lock.Unlock()

	write(t, b, s, "roles/second", map[string]any{"project_id": "project-1", "bucket": "aether"})

	got := principals(policyOf(t, fake, "aether").Statement[0])
	for _, want := range []string{"id-s3-first", "id-s3-second"} {
		if !slices.Contains(got, want) {
			t.Fatalf("expected %s among the consumers, got %v", want, got)
		}
	}
}

func TestTheEngineNeverIssuesAKeyForAnotherRole(t *testing.T) {
	fake := newFakeSelectel(t)
	b, s := testBackend(t, fake)

	write(t, b, s, "roles/first", map[string]any{"project_id": "project-1", "bucket": "aether"})

	fake.lock.Lock()
	fake.readableBy = map[string]struct{}{"id-" + policyReaderName: {}}
	fake.keyOwners = map[string]string{}
	fake.lock.Unlock()

	write(t, b, s, "roles/second", map[string]any{"project_id": "project-1", "bucket": "aether"})

	fake.lock.Lock()
	defer fake.lock.Unlock()
	for _, owner := range fake.keyOwners {
		if owner == "id-s3-first" {
			t.Fatal("provisioning one role must never mint a key for another")
		}
	}
}
