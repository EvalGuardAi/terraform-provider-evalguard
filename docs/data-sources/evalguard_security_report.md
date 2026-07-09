---
page_title: "evalguard_security_report data-sources"
description: |-
  Reads the current security report (findings, severity counts) for a project.
---

# evalguard_security_report (Data-sources)

Reads the current security report (findings, severity counts) for a project.

## Example Usage

```terraform
data "evalguard_security_report" "current" {
  project_id = evalguard_project.example.id
}

output "critical_findings" {
  value = data.evalguard_security_report.current.critical_count
}
```

## Schema

### Required

- `project_id`

### Read-Only

- `id`
- `total_findings`
- `critical_count`
- `findings`
- `scanned_at`

