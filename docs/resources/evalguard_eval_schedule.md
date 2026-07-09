---
page_title: "evalguard_eval_schedule resources"
description: |-
  Manages a recurring evaluation schedule on an EvalGuard project.
---

# evalguard_eval_schedule (Resources)

Manages a recurring evaluation schedule on an EvalGuard project.

## Example Usage

```terraform
resource "evalguard_eval_schedule" "nightly" {
  project_id      = evalguard_project.example.id
  name            = "nightly-regression"
  cron_expression = "0 3 * * *"
  enabled         = true

  config = jsonencode({
    model   = "gpt-4"
    scorers = ["exact-match", "faithfulness"]
  })
}
```

## Schema

### Required

- `project_id` (String, Forces new resource)
- `name` (String)
- `cron_expression` (String) Cron expression controlling when the eval runs, e.g. `0 3 * * *`.
- `config` (String) Eval configuration, encoded with `jsonencode(...)`.

### Optional

- `description` (String)
- `dataset_id` (String)
- `enabled` (Boolean) Defaults to `true`.

### Read-Only

- `id` (String)
- `next_run_at` (String)
- `created_at` (String)
