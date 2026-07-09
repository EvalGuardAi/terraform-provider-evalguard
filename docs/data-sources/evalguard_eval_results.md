---
page_title: "evalguard_eval_results data-sources"
description: |-
  Reads the latest evaluation results for a project (optionally filtered by dataset).
---

# evalguard_eval_results (Data-sources)

Reads the latest evaluation results for a project (optionally filtered by dataset).

## Example Usage

```terraform
data "evalguard_eval_results" "latest" {
  project_id = evalguard_project.example.id
  dataset_id = "ds_checkout_golden"
}

output "sample_count" {
  value = data.evalguard_eval_results.latest.sample_count
}
```

## Schema

### Required

- `project_id`

### Optional

- `dataset_id`

### Read-Only

- `id`
- `results`
- `sample_count`

