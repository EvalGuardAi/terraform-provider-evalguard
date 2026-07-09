---
page_title: "evalguard_firewall_rule resources"
description: |-
  Manages a runtime firewall rule (block/allow/transform/rate_limit/content_filter) with match conditions.
---

# evalguard_firewall_rule (Resources)

Manages a runtime firewall rule (block/allow/transform/rate_limit/content_filter) with match conditions.

## Example Usage

```terraform
resource "evalguard_firewall_rule" "block_pii" {
  project_id  = evalguard_project.example.id
  name        = "block-ssn-in-prompt"
  description = "Reject prompts that contain a US SSN"
  rule_type   = "block"
  priority    = 10
  enabled     = true

  conditions {
    field    = "prompt"
    operator = "regex"
    value    = "\b\d{3}-\d{2}-\d{4}\b"
  }

  action_config = {
    message = "Request blocked: sensitive data detected."
  }
}
```

## Schema

### Required

- `project_id`
- `name`
- `rule_type`
- `conditions`

### Optional

- `description`
- `priority`
- `enabled`
- `action_config`

### Read-Only

- `id`

