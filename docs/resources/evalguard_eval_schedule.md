---
page_title: "evalguard_eval_schedule resources"
description: |-
  Manages a scheduled evaluation run with regression alerting and notification channels.
---

# evalguard_eval_schedule (Resources)

Manages a scheduled evaluation run with regression alerting and notification channels.

## Example Usage

```terraform
resource "evalguard_eval_schedule" "nightly" {
  project_id           = evalguard_project.example.id
  name                 = "nightly-regression"
  dataset_id           = "ds_checkout_golden"
  model                = "gpt-4o-mini"
  metrics              = ["faithfulness", "answer-relevance", "toxicity"]
  cron                 = "0 */6 * * *"
  enabled              = true
  notify_on_regression = true
  regression_threshold = 0.05

  notification_channels {
    type   = "slack"
    target = "https://hooks.slack.com/services/T000/B000/XXXX"
  }
}
```

## Schema

### Required

- `project_id`
- `name`
- `dataset_id`
- `model`
- `metrics`
- `cron`

### Optional

- `enabled`
- `notify_on_regression`
- `regression_threshold`
- `notification_channels`

### Read-Only

- `id`
- `last_run_at`
- `next_run_at`

