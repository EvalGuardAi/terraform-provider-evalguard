---
page_title: "evalguard_firewall_rule resources"
description: |-
  Manages a firewall rule on an EvalGuard project.
---

# evalguard_firewall_rule (Resources)

Manages a firewall rule on an EvalGuard project.

## Example Usage

```terraform
resource "evalguard_firewall_rule" "block_injection" {
  project_id = evalguard_project.example.id
  name       = "block-prompt-injection"
  type       = "regex"
  priority   = 10
  enabled    = true

  condition = jsonencode({
    pattern = "(?i)ignore (all )?previous instructions"
  })

  action = jsonencode({
    type = "block"
  })

  regions = ["EU", "US"]
}
```

## Schema

### Required

- `project_id` (String, Forces new resource) Project the rule belongs to.
- `name` (String)
- `type` (String) Rule type, e.g. `regex`, `semantic`, `pii`.
- `condition` (String) Match condition, encoded with `jsonencode(...)`.
- `action` (String) Action, encoded with `jsonencode(...)`.

### Optional

- `description` (String)
- `priority` (Number) Defaults to `100`.
- `enabled` (Boolean) Defaults to `true`.
- `tags` (List of String)
- `regions` (List of String) Jurisdiction tokens the rule applies in (`EU`, `US`, `APAC`, an ISO-3166 alpha-2 code, or `GLOBAL`). Empty means everywhere.

### Read-Only

- `id` (String)

`condition` and `action` are free-form JSON on the server, so they are modelled as `jsonencode(...)` strings rather than a lossy flattened map. The provider canonicalizes them on read, so a round-trip does not produce a perpetual diff.
