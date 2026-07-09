# Publishing terraform-provider-evalguard

> **This is the standalone published mirror** of
> `EvalGuardAi/evalguard` → `packages/terraform-provider` (the source of truth).
> Because it's a dedicated repo, releases are tagged **`vX.Y.Z`** (the Terraform
> Registry convention) — not the monorepo's `terraform-provider-v*` prefix — and
> both workflows run from the repo root. Re-sync source changes from the monorepo
> before cutting a release.

The provider is **CI-gated and release-ready**. Everything that can be automated
is: build, race+coverage tests, `gofmt`, `go vet`, `golangci-lint`, `gosec`,
`govulncheck`, `terraform validate` of every example, GoReleaser multi-platform
signed builds, and a tag-triggered release workflow. What remains are the
**one-time account/key actions only the org owner can perform** — you cannot
grant an automated agent a HashiCorp Registry identity or a signing key.

## One-time setup (org owner)

1. **Generate a GPG signing key** (RSA 4096 or Ed25519), no expiry or a long one:
   ```bash
   gpg --full-generate-key
   gpg --armor --export-secret-keys <KEY_ID> > private.asc   # keep secret
   gpg --armor --export <KEY_ID>                              # public — for the registry
   ```
2. **Add repo secrets** (Settings → Secrets → Actions):
   - `TERRAFORM_GPG_PRIVATE_KEY` — contents of `private.asc`
   - `TERRAFORM_GPG_PASSPHRASE` — the key passphrase
3. **Register on the Terraform Registry** (https://registry.terraform.io):
   - Sign in with the `EvalGuardAi` GitHub org.
   - Publish → add the provider → upload the **public** GPG key.
   - The registry requires the provider to live in a repo named
     **`terraform-provider-evalguard`**. This code is a monorepo submodule at
     `packages/terraform-provider`; publish via one of:
     - **(a) Dedicated mirror repo** (recommended, mirrors the Go SDK flow):
       push `packages/terraform-provider/` to `EvalGuardAi/terraform-provider-evalguard`,
       carry `.goreleaser.yml` + this release workflow there, and tag `vX.Y.Z`.
     - **(b) Monorepo release**: keep everything here; the registry ingests
       GitHub Releases created by `release-terraform-provider.yml`. Confirm the
       registry accepts the monorepo repo name during the add-provider step.

## Cutting a release

```bash
# Verify locally first (no publish):
cd packages/terraform-provider
go test -race ./... && gofmt -l . && go vet ./...

# Dry run the release pipeline (build + sign, no GitHub release):
#   Actions → "Release Terraform Provider" → Run workflow → dry_run = true

# Real release — tag it (monorepo-safe prefix):
git tag terraform-provider-v1.0.0
git push origin terraform-provider-v1.0.0
```

The release workflow imports the GPG key, runs GoReleaser, and attaches the
zip archives, `SHA256SUMS`, its `.sig`, and the manifest to a GitHub Release.
The registry picks up the tagged release and lists the version.

## What ships in v1.0.0

- **5 resources** (real `/api/v1` CRUD + tests): `evalguard_project`,
  `evalguard_api_key`, `evalguard_firewall_rule`, `evalguard_eval_schedule`,
  `evalguard_gateway_policy`.
- **2 data sources**: `evalguard_eval_results`, `evalguard_security_report`.
- Security posture: https-only `base_url` (Bearer-token leak protection),
  sensitive credential fields, bounded idempotency-safe retries.

## After publishing

Only then update the marketing copy that currently (correctly) says EvalGuard
has no published provider:
`apps/web/src/app/(marketing)/compare/[slug]/data.ts` (the `"Terraform provider"`
row) and the pitch decks. Do **not** flip those before the registry listing is
live — an unpublished "published" claim is the exact overclaim class we audit for.
