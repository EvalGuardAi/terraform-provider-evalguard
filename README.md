# EvalGuard Terraform Provider

**Status: release-ready. 5 production-grade resources + 2 data sources, CI-gated
and security-hardened. Registry publish is one founder action away — see
[PUBLISHING.md](./PUBLISHING.md).**

CI (`.github/workflows/terraform-provider-ci.yml`) runs on every change: `gofmt`,
`go vet`, `go test -race` + coverage, `golangci-lint`, **gosec** (SAST),
**govulncheck** (known-vuln deps), and `terraform validate` of every example.
Security posture: https-only `base_url` (the API key is a Bearer token — a
plaintext endpoint is a hard error), sensitive credential fields, and bounded
idempotency-safe retries (429 always; 5xx only on idempotent verbs — never a
double-create). Release: signed multi-platform builds via GoReleaser
(`.goreleaser.yml` + `release-terraform-provider.yml`).

T1.3 (2026-05-21) removed the 15 schema-only stub resources that previously shipped with no-op CRUD handlers. The provider binary now exposes ONLY resources that execute real HTTP against the EvalGuard `/api/v1` surface — `terraform apply` always makes a real state change OR fails loud.

- `evalguard_project` → `/api/v1/projects` (POST/GET/PUT/DELETE)
- `evalguard_api_key` → `/api/v1/api-keys` (POST/GET/PUT/DELETE)
- `evalguard_firewall_rule` → `/api/v1/firewall/rules` (POST/GET/PUT/DELETE)
- `evalguard_eval_schedule` → `/api/v1/eval-schedules` (POST/GET/PUT/DELETE)
- `evalguard_gateway_policy` → `/api/v1/gateway/policies` (POST `action=create-rule` + GET list + DELETE ?id — no PUT, update = delete+create)

All five carry the `x-requested-with: terraform-provider` header required by `createApiHandler`'s CSRF gate. Read paths surface 404 as `d.SetId("")` so a state-drift caused by an out-of-band delete recovers cleanly on the next plan.

The previously-stubbed 15 resources are tracked in [`ROADMAP.md`](./ROADMAP.md) with the bar for promotion: typed `<name>API` struct, mapping helpers, 404-aware Read, plus integration tests against the `httptest` mock in `main_test.go`.

## Verification

```bash
cd packages/terraform-provider
go build ./...   # clean
go test -v ./... # 13/13 pass (httptest mock + per-resource integration)
go vet ./...     # clean
```

## What works today

- **Real CRUD for the 5 resources above** — `terraform apply` creates/updates/deletes against a real EvalGuard org. Read clears state when the resource was deleted out-of-band (404 → empty ID).
- Resource schemas — all 5 documented in `main.go`.
- `terraform validate` against config files using these resources.
- `terraform plan` — produces a plan; state IDs are now backed by the API's persisted id.
- `terraform import` — schemas declare `Importer: ImportStatePassthroughContext`.

## What does NOT work today

- The remaining 15 resources + 2 data sources still use the pre-D5 stub CRUD. Their handlers set a deterministic local id but do not hit the API. Promote each by mirroring the D5 pattern (typed struct + `httpDo` calls).
- `terraform apply` for those 15 stubbed resources will succeed locally and drift.

## Roadmap

The intended sequencing for promoting resources from schema-preview to real CRUD:

1. `evalguard_project` — needed for everything else; gate first.
2. `evalguard_api_key` — needed to test other resources.
3. `evalguard_firewall_rule` — high-value first real resource.
4. `evalguard_eval_schedule` — recurring evals.
5. `evalguard_gateway_policy` — routing config.

The remaining 15 resources + 2 data sources will follow once the first five are stable + acceptance-tested.

## Why ship the schema-preview at all?

Even without real apply, the schemas have value:

- IaC reviewers can write and review `.tf` files against a stable shape.
- The provider catalog becomes part of the public roadmap.
- Internal teams can prototype Terraform-driven workflows without waiting on full CRUD.

## Comparison with marketing copy

`apps/web/src/app/(marketing)/compare/[slug]/page.tsx` (line 888) accurately states EvalGuard does **not** ship a published Terraform provider yet. This package is the in-progress work that backs that claim — kept in-source as a development reference, not yet shipped to the Terraform Registry.

When CRUD is wired up and acceptance tests are green, that marketing line will flip from "No" to "Yes" in the same PR.
