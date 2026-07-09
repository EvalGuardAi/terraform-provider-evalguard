// Self-contained example exercising every resource. This is the config CI runs
// `terraform validate` against (the per-resource files under
// examples/resources/** are registry doc snippets — real, fmt-checked HCL, but
// they reference a shared project and omit the provider block, so they are not
// meant to validate standalone).

terraform {
  required_providers {
    evalguard = {
      source  = "EvalGuardAi/evalguard"
      version = "~> 1.1"
    }
  }
}

provider "evalguard" {
  # api_key is read from EVALGUARD_API_KEY by default.
}

variable "evalguard_org_id" {
  type        = string
  description = "Organization that owns these resources."
}

resource "evalguard_project" "example" {
  org_id = var.evalguard_org_id
  name   = "checkout-assistant"
  slug   = "checkout-assistant"

  settings = jsonencode({
    retention_days = 30
  })
}

resource "evalguard_api_key" "ci" {
  org_id = var.evalguard_org_id
  name   = "ci-firewall-check"
  scopes = ["firewall:check"]
}

resource "evalguard_firewall_rule" "block_injection" {
  project_id = evalguard_project.example.id
  name       = "block-prompt-injection"
  type       = "regex"
  priority   = 10

  condition = jsonencode({
    pattern = "(?i)ignore (all )?previous instructions"
  })

  action = jsonencode({
    type = "block"
  })
}

resource "evalguard_eval_schedule" "nightly" {
  project_id      = evalguard_project.example.id
  name            = "nightly-regression"
  cron_expression = "0 3 * * *"

  config = jsonencode({
    model   = "gpt-4"
    scorers = ["exact-match"]
  })
}

resource "evalguard_gateway_policy" "deny_external_http" {
  project_id = evalguard_project.example.id
  name       = "deny-external-http"
  effect     = "deny"
  priority   = 50

  conditions = jsonencode({
    tools = ["http.get"]
  })
}

output "ci_api_key" {
  value     = evalguard_api_key.ci.key
  sensitive = true
}
