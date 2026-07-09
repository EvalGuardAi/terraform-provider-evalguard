---
page_title: "evalguard_api_key resources"
description: |-
  Manages an EvalGuard platform API key. The secret is readable only at creation time.
---

# evalguard_api_key (Resources)

Manages an EvalGuard platform API key. The raw secret is returned exactly once, when the key is created.

## Example Usage

```terraform
resource "evalguard_api_key" "ci" {
  org_id = var.evalguard_org_id
  name   = "ci-firewall-check"
  scopes = ["firewall:check"]
}

output "ci_key" {
  value     = evalguard_api_key.ci.key
  sensitive = true
}
```

## Schema

### Required

- `org_id` (String, Forces new resource) Organization that owns the key.
- `name` (String, Forces new resource) Key name, unique within the org.

### Optional

- `scopes` (List of String, Forces new resource) Scopes granted to the key, e.g. `firewall:check`. A key with no scopes is unauthorized for every scoped route.
- `expires_at` (String, Forces new resource) RFC 3339 expiry timestamp. Omit for a non-expiring key.

Name, scopes, and expiry are immutable server-side, so changing any of them replaces the key.

### Read-Only

- `id` (String)
- `key` (String, Sensitive) The raw API key. Populated only on creation — after a refresh or `terraform import` it is empty, because the server stores only a SHA-256 hash.
- `key_prefix` (String)
- `revoked` (Boolean)
- `created_at` (String)

## Revocation

`terraform destroy` soft-revokes the key (`DELETE /api/v1/api-keys/{id}`); the row is retained so audit history stays intact. If a key is revoked outside Terraform, the next `plan` sees it as gone and schedules a replacement.
