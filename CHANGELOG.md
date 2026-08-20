# Changelog

## [1.3.1](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.3.0...v1.3.1) (2026-08-20)


### Bug Fixes

* stop reporting leased keys as orphans ([#8](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/issues/8)) ([660ba7f](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/660ba7f27db64fcf3fa2d53d8227a0279d47a40b))

## [1.3.0](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.2.0...v1.3.0) (2026-08-20)


### Features

* adopt a bucket the engine cannot read yet ([6bef766](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/6bef766306d790a6b5a1a6cb8df105f29b423355))

## [1.2.0](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.1.1...v1.2.0) (2026-08-20)


### Features

* rotate the engine password from the engine ([9cd5916](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/9cd5916f934ed49b1240ab7100ca45d6d09017f5))

## [1.1.1](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.1.0...v1.1.1) (2026-08-20)


### Bug Fixes

* read policies as the engine, not as a consumer ([00303d5](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/00303d53ca6165c63efd5d4731b8c511eb0ae665))

## [1.1.0](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.0.2...v1.1.0) (2026-08-20)


### Features

* borrow a sibling role to read a bucket policy ([e2c638e](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/e2c638e995b6e4c382ce0665c228ebdb9ec96186))

## [1.0.2](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.0.1...v1.0.2) (2026-08-20)


### Bug Fixes

* send the payload hash header when signing s3 requests ([e94e07a](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/e94e07ab208b670ebd07044c7811a57b747c0126))

## [1.0.1](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/compare/v1.0.0...v1.0.1) (2026-08-20)


### Bug Fixes

* read the bucket policy as the role's own user ([29ec42a](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/29ec42a5f7b04c86d3dea99fef0537515e44e1d7))

## 1.0.0 (2026-08-20)


### Features

* provision the service user and bucket policy from the role ([01ff7e3](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/01ff7e32084e659f12a6e6c97a49c0175181ee0b))
* selectel s3 secrets engine ([f4b214c](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/f4b214c88a28b4588711fe4246a8a80b93d4e73e))


### Bug Fixes

* scope the iam token to the account ([3fc1d1c](https://github.com/clique-it-tech/vault-plugin-secrets-selectel-s3/commit/3fc1d1c7ea91fcbb414c3a8d918985ac2573abbf))
