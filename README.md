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

The engine authenticates to Selectel as a service user that is allowed to manage
S3 credentials through the IAM API. Give that user the `iam_admin` role, or the
narrowest role your account offers that still permits credential management.

```shell
vault write selectel/config \
  account_id=123456 \
  username=vault \
  password=... \
  project_name=production
```

`auth_url` defaults to `https://cloud.api.selcloud.ru/identity/v3` and `iam_url`
to `https://api.selectel.ru`; both can be overridden. The password is stored
seal-wrapped and is never returned by a read.

## Roles

```shell
vault write selectel/roles/storage \
  service_user_id=<uuid of the service user> \
  project_id=<uuid of the project> \
  ttl=1h \
  max_ttl=8h
```

| Field | Meaning |
| --- | --- |
| `service_user_id` | Whose permissions the issued key inherits |
| `project_id` | Project the key is created in |
| `ttl` | How long a key lives before Vault deletes it |
| `max_ttl` | Ceiling for renewals, capped at 24h by the engine |

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
