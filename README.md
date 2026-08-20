# Vault Plugin: Selectel S3 Secrets Backend

A [HashiCorp Vault](https://www.vaultproject.io) secrets engine that issues Selectel S3 access keys on demand and deletes
them when the lease ends.

Selectel keys never expire on their own. Once a key exists it works until
somebody removes it, which is why long-lived keys end up copied into CI
variables, backup jobs and laptops. This engine makes the key a leased object:
Vault creates it when a client asks, and deletes it when the lease is revoked or
runs out.

## How access is scoped

Selectel attaches bucket permissions to a **service user**, not to an individual
key. A key inherits exactly what its service user can do, and nothing narrower.

That shapes how you set this up: create one service user per consumer, name it
in the bucket policy of the bucket it may touch, and give it the role it needs
(`s3.user` or `s3.bucket.user`). Then bind one Vault role to each service user.
A Vault policy that grants `creds/backups` cannot reach the bucket behind
`creds/storage`, because the two roles point at different service users.

Trying to scope a single key more narrowly than its user is not possible through
the API, and rewriting a bucket policy on every issue would race with itself.

## Build

```shell
make build          # host binary, into bin/
make linux          # linux/amd64, into bin/
make test
make lint
```

## Install

Register the binary and enable the engine:

```shell
vault plugin register \
  -sha256="$(sha256sum vault-plugin-secrets-selectel-s3-linux-amd64 | cut -d' ' -f1)" \
  -command=vault-plugin-secrets-selectel-s3 \
  -version=v1.0.0 \
  secret vault-plugin-secrets-selectel-s3

vault secrets enable -path=selectel -plugin-version=v1.0.0 vault-plugin-secrets-selectel-s3
```

## Configure

The engine authenticates to Selectel as a service user holding the `iam.admin`
role, which is what Selectel requires to issue S3 keys to other users. That role
is granted on the account, so the engine asks Keystone for an **account-scoped**
token, not a project-scoped one — a service user with no project role still
works, and in fact needs none.

```shell
vault write selectel/config \
  account_id=123456 \
  user_id=<id of the service user> \
  password=...
```

`account_id` is the account number, which Keystone knows as the domain name.
`user_id` is the service user's id, not its login: authenticating by id avoids
having to name the domain twice. `auth_url` defaults to
`https://cloud.api.selcloud.ru/identity/v3` and `iam_url` to
`https://api.selectel.ru`; both can be overridden. The password is stored
seal-wrapped and is never returned by a read.

## Roles

Writing a role provisions everything it needs:

```shell
vault write selectel/roles/storage \
  project_id=<uuid of the project> \
  bucket=aether \
  ttl=1h \
  max_ttl=8h
```

The engine creates a service user named `s3-<role>` with the `s3.user` role, then
adds it to the bucket's policy under the statement id `allow-vault-issued`.
Statements it did not write are left alone, and rewriting an unchanged role
changes nothing. Deleting the role reverses both steps.

| Field | Meaning |
| --- | --- |
| `project_id` | Project the service user and its keys live in |
| `bucket` | Bucket to grant. Omit it to manage the policy yourself |
| `service_user_id` | Bind to an existing user instead of creating one |
| `ttl` | How long a key lives before Vault deletes it |
| `max_ttl` | Ceiling for renewals, capped at 24h by the engine |

### Why a bucket policy needs a second identity

Selectel refuses `PutBucketPolicy` to anything below the `s3.admin` role, and
that role carries full control of every bucket in the project. Rather than hold
it permanently, the engine creates a service user with `s3.admin`, uses its key
for the single policy call, and deletes the user before returning — including
when the call fails. The engine's own credential keeps `iam.admin` and nothing
more, so a leak of the configured password cannot reach object data.

## Issue a key

```shell
vault read selectel/creds/storage
```

```
Key                Value
---                -----
lease_id           selectel/creds/storage/9Qm...
lease_duration     1h
lease_renewable    true
access_key         ...
secret_key         ...
```

`vault lease revoke <lease_id>` deletes the key immediately.

## Sweeping orphans

If Vault cannot reach Selectel while a lease is being revoked, the key stays
behind and keeps working — there is no server-side expiry to fall back on. The
sweep path finds keys this engine minted that no live lease owns:

```shell
vault read selectel/sweep/storage                 # report only
vault write selectel/sweep/storage delete=true    # remove them
```

Keys the engine did not create are recognised by their name and left untouched,
so a sweep is safe to run against a service user that also holds a key you
manage by hand.

Run it on a schedule. It is the only backstop this provider allows.

## Credits

Written by the Clique team with [Claude](https://claude.com/claude-code).

## License

Apache-2.0. See [LICENSE](LICENSE).
