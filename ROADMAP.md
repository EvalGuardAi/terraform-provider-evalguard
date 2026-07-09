# Terraform Provider Roadmap

> **Status: v1.1.0.** 5 resources with real `/api/v1` CRUD, pinned by contract tests against the server's zod schemas. v1.0.0 was published but non-functional — see README.

## Shipped (BETA, 5 resources)

| Resource | API path | Tests |
|---|---|---|
| `evalguard_project` | `/projects` | ✅ full CRUD + 404→state-clear |
| `evalguard_api_key` | `/api-keys` | ✅ create + delete |
| `evalguard_firewall_rule` | `/firewall/rules` | ✅ create + read |
| `evalguard_eval_schedule` | `/evals/schedules` | ✅ create |
| `evalguard_gateway_policy` | `/gateway/policies` | ✅ create + delete |

Plus shared infrastructure:
- `httpDo()` helper with envelope-unwrap, typed `apiNotFoundError`, CSRF header (`x-requested-with`)
- Provider schema validation (`InternalValidate()`)
- Auth via `EVALGUARD_API_KEY` env or `api_key` provider attribute
- 0 data sources. `evalguard_eval_results` and `evalguard_security_report` were removed in v1.1.0: their Read functions returned nil without calling the API. They return once backed by a real read.

## Bar for promotion to BETA

Every resource added to `ResourcesMap` must:

1. Have `resource<Name>{Create,Read,Update,Delete}` functions that call `httpDo()` against a real `/api/v1` path.
2. Have a typed `<name>API` struct + `<name>FromState` / `<name>ToState` mapping helpers.
3. Map a 404 from Read to `d.SetId("")` so drift is recoverable.
4. Have integration tests in `main_test.go` covering at minimum:
   - Create POSTs the right body
   - Read populates state correctly
   - Read on 404 clears state without error
   - Delete hits the right path and clears state
5. Pass `go test ./...` + `go vet ./...` + `go build ./...`.

## Deferred — held until each gets a real wiring

The following 15 resources were previously declared as schema-only stubs. They produced a `terraform plan` w/ the right shape but a `terraform apply` made **zero state changes upstream** (`genericCRUD` returned `nil` from every CRUD callback). They have been **removed from the binary** until each one ships against a real `/api/v1` path.

### Tier 1 (high-priority, scope-clear)

| Resource | API path | Why |
|---|---|---|
| `evalguard_scorer` | `/scorers` | Custom LLM-judge / regex / embedding scorers |
| `evalguard_dataset` | `/datasets` | Test dataset registration |
| `evalguard_provider_key` | `/provider-keys` | LLM provider key w/ optional `vault_ref` |
| `evalguard_member` | `/org/members` | Org member invite + role |
| `evalguard_team` | `/teams` | RBAC scope unit |
| `evalguard_alert` | `/monitoring/alerts` | Cost/drift/error-rate alerts |

### Tier 2 (depends on adjacent backend work)

| Resource | Blocked on |
|---|---|
| `evalguard_audit_destination` | SIEM webhook config table — partially shipped |
| `evalguard_compliance_framework_subscription` | Per-org subscription record |
| `evalguard_eval_run` | Schema discriminating one-shot vs scheduled |
| `evalguard_role` | Custom RBAC role admin route |
| `evalguard_vault_config` | Vault resolver public API |
| `evalguard_mcp_server` | MCP server admin API |
| `evalguard_mcp_tool_permission` | Per-tool RBAC admin API |
| `evalguard_persona` | Red-team persona public API |
| `evalguard_red_team_config` | Closed-loop red-team public API |

## Versioning

| Version | Scope |
|---|---|
| `1.1.0` | Five working resources (current branch). Publishes to the Terraform Registry as `EvalGuardAi/evalguard` once the API fixes in this PR are deployed. |
| `0.2.0` | Adds 6 tier-1 resources from the deferred list |
| `1.0.0` | All tier-1 + tier-2 resources real; documented compatibility w/ Terraform 1.7+ AND OpenTofu 1.8+ |

## Verification

Run from `packages/terraform-provider/`:

```bash
go build ./...
go test -v ./...
go vet ./...
```

Currently: `go test -v ./...` runs 12 integration tests against an `httptest`-based mock of `/api/v1`. Add new tests under the matching `TestResource<Name>_*` naming when shipping a new resource.
