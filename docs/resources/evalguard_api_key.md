---
page_title: "evalguard_api_key resources"
description: |-
  Manages a scoped EvalGuard API key. The secret is returned once on create; only key_preview is retained.
---

# evalguard_api_key (Resources)

Manages a scoped EvalGuard API key. The secret is returned once on create; only key_preview is retained.

## Example Usage

```terraform
resource "evalguard_api_key" "ci" {
  project_id = evalguard_project.example.id
  name       = "ci-pipeline"
  scopes     = ["eval:read", "eval:write", "security:scan"]
  expires_at = "2027-01-01T00:00:00Z"
}

# The generated key is returned once; store it securely. Only the first 8
# characters are retained in state (key_preview, marked sensitive).
output "api_key_preview" {
  value = evalguard_api_key.ci.key_preview
}
```

## Schema

### Required

- `project_id`
- `name`

### Optional

- `scopes`
- `expires_at`

### Read-Only

- `id`
- `key_preview`
- `created_at`

