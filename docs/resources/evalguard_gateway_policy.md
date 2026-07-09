---
page_title: "evalguard_gateway_policy resources"
description: |-
  Manages an agent gateway policy rule (allow/deny) on an EvalGuard project.
---

# evalguard_gateway_policy (Resources)

Manages an agent gateway policy rule on an EvalGuard project.

## Example Usage

```terraform
resource "evalguard_gateway_policy" "deny_external_http" {
  project_id  = evalguard_project.example.id
  name        = "deny-external-http"
  description = "Agents may not call arbitrary external endpoints"
  effect      = "deny"
  priority    = 50

  conditions = jsonencode({
    tools = ["http.get", "http.post"]
  })
}
```

## Schema

### Required

- `project_id` (String, Forces new resource)
- `name` (String, Forces new resource)
- `effect` (String, Forces new resource) Either `allow` or `deny`.

### Optional

- `description` (String, Forces new resource)
- `priority` (Number, Forces new resource) Defaults to `100`.
- `conditions` (String, Forces new resource) Match conditions, encoded with `jsonencode(...)`.

### Read-Only

- `id` (String)
- `created_at` (String)

The API exposes no update verb for a policy rule, so every attribute forces a new resource: Terraform replaces the rule rather than reporting a change it cannot make.
