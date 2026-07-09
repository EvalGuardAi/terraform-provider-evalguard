---
page_title: "evalguard_project resources"
description: |-
  Manages an EvalGuard project — the top-level container for evals, firewall rules, and gateway policies.
---

# evalguard_project (Resources)

Manages an EvalGuard project — the top-level container for evals, firewall rules, and gateway policies.

## Example Usage

```terraform
resource "evalguard_project" "example" {
  name        = "checkout-assistant"
  description = "LLM checkout assistant — evals, firewall, and gateway config"
  environment = "production"

  tags = {
    team = "payments"
    tier = "critical"
  }
}
```

## Schema

### Required

- `name`

### Optional

- `description`
- `environment`
- `tags`

### Read-Only

- `id`
- `created_at`

