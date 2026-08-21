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
| `max_ttl` | Ceiling for renewals |

Vault clamps both to the mount's own limits. Set `max_lease_ttl` on the mount
deliberately: a Selectel key never expires by itself, so the lease is the only
thing that ends it.

### Why a bucket policy takes two more identities

Selectel splits the two halves of managing a policy between different roles, and
gives neither both:

* **Writing** needs `s3.admin`, which carries full control of every bucket in the
  project. The engine will not hold that permanently. It creates a service user
  with `s3.admin`, uses its key for the single policy call, and deletes the user
  before returning — including when the call fails.
* **Reading** is refused to `s3.admin` and allowed only to a principal the policy
  already names. The engine keeps one long-lived user for this, `s3-vault-policy-reader`,
  and writes it into each managed bucket under its own statement granting nothing
  but `s3:GetBucketPolicy`.

Consumers' service users are never used for either. Provisioning one role never
issues a credential belonging to another, so a Vault policy that grants one role
cannot cause a key to appear on someone else's user.

A bucket that existed before the engine has to be handed over once, because
nobody the engine controls is named in its policy yet. Do that through the engine
rather than by hand:

```shell
aws --endpoint-url "$ENDPOINT" s3api get-bucket-policy --bucket aether \
  --output text --query Policy > policy.json

vault write selectel/config/adopt-bucket/aether \
  project_id=<uuid> policy=@policy.json
```

Read the policy with any key the bucket already names. The engine writes itself
in, keeping every statement it was handed, and then proves it can read the bucket
before reporting success. Adopting the same bucket again is a no-op, and a bucket
created after the engine needs no adoption at all.

## Trimming a bucket policy

Buckets that predate the engine often carry a blanket statement — every principal
in the account, every action — left over from before anything scoped access
properly. Remove it by name:

```sh
vault write selectel/config/drop-statement/clq-expo-ota \
  project_id=<project> \
  sids=allow-all-sa
```

```
Key          Value
---          -----
bucket       clq-expo-ota
removed      [allow-all-sa]
not_found    []
remaining    [allow-vault-policy-reader allow-vault-issued]
```

Statements are named explicitly rather than filtered by shape, because "drop
everything the engine did not write" is the wrong instrument: a bucket serving a
CDN needs its anonymous `s3:GetObject` rule, and a blunt sweep would take it out
along with the blanket grant. Naming what goes makes the dangerous case
impossible to reach by accident.

Two refusals are built in. The engine's own statements cannot be dropped, since
losing them costs it the access it needs to manage the bucket at all; and a
request that would leave the policy with no statements is rejected rather than
emptying it. The bucket must already be adopted, because the engine reads the
policy before editing it.

## Rotating the engine's own password

The password written at configuration time is the one credential the engine
cannot lease. Rotate it as soon as the engine works, and on a schedule after
that:

```shell
vault write -f selectel/config/rotate-root
```

The engine generates a new password, sets it in Selectel and stores it; from
then on nobody knows it, including whoever first configured the engine. Storage
is written before Selectel, so a rotation Selectel refuses is rolled back rather
than leaving the engine locked out of its own account.

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

## A key that outlives the read

A role hands out a new key every time it is read, which suits a consumer that asks once when it
starts. Some consumers cannot work that way: a CSI driver keeping a Kubernetes secret in sync
re-reads on a timer, and CNPG's backup plugin only knows how to read a secret someone else keeps
fresh. At a two-minute poll a dynamic role would mint seven hundred keys a day.

A static role holds one key instead:

```sh
vault write selectel/static-roles/backups \
  project_id=<project> \
  bucket=clq-backups

vault read selectel/static-creds/backups
```

Reading returns the same key every time and mints nothing. The key changes only when you say so:

```sh
vault write -f selectel/rotate-role/backups
```

Rotation mints the new key and stores it before deleting the old one, so a failure halfway leaves
the role holding a key that works rather than none. Consumers pick the new one up on their next
read; anything holding the previous key keeps working until it re-reads, so rotate with that
window in mind.

A static role gets its own service user, named `s3-static-<role>` rather than `s3-<role>`, and the
engine refuses a static role whose name a dynamic role already uses — sharing one service user
between the two would let a dynamic revocation delete the static key. For the same reason the
sweep ignores static keys entirely: their age says nothing about whether they are still in use.

There is no schedule. Rotation is a command you run, which keeps the engine free of opinions about
how often a key should change.

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
