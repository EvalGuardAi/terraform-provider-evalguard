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
  org_id = var.evalguard_org_id
  name   = "checkout-assistant"
  slug   = "checkout-assistant"

  settings = jsonencode({
    retention_days = 30
  })
}
```

## Schema

### Required

- `org_id` (String) Organization that owns the project. The caller must be a member of it. Changing this forces a new project.
- `name` (String) Human-readable project name, 2–50 characters.
- `slug` (String) URL-safe identifier, unique within the org: lowercase alphanumeric and hyphens, 2–50 characters.

### Optional

- `settings` (String) Free-form project settings, encoded with `jsonencode(...)`. Applied with a follow-up `PATCH` after creation, because the create endpoint does not accept it.

### Read-Only

- `id` (String)
- `created_at` (String)
- `updated_at` (String)

## Import

```shell
terraform import evalguard_project.example <project-uuid>
```

After importing, set `org_id` in your configuration to match the project's organization.

## Deleting a project is destructive

`terraform destroy` calls `DELETE /api/v1/projects/{id}`. Roughly 80 tables
reference a project with `ON DELETE CASCADE` — traces, gateway logs, eval runs,
security scans, datasets, and prompts among them — so destroying a project
destroys its entire history. The API requires the `admin` role for this and
records it in the audit log.
