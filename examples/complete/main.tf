// Self-contained example exercising every resource + data source. This is the
// config CI runs `terraform validate` against (the per-resource files under
// examples/resources/** are registry doc snippets — real, fmt-checked HCL, but
// they reference a shared project and omit the provider block, so they are not
// meant to validate standalone).

terraform {
  required_providers {
    evalguard = {
      source  = "EvalGuardAi/evalguard"
      version = "~> 1.0"
    }
  }
}

provider "evalguard" {
  # api_key is read from EVALGUARD_API_KEY by default.
}

resource "evalguard_project" "example" {
  name        = "checkout-assistant"
  description = "LLM checkout assistant"
  environment = "production"

  tags = {
    team = "payments"
  }
}

resource "evalguard_api_key" "ci" {
  project_id = evalguard_project.example.id
  name       = "ci-pipeline"
  scopes     = ["eval:read", "eval:write", "security:scan"]
}

resource "evalguard_firewall_rule" "block_pii" {
  project_id = evalguard_project.example.id
  name       = "block-ssn-in-prompt"
  rule_type  = "block"
  priority   = 10

  conditions {
    field    = "prompt"
    operator = "regex"
    value    = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  }
}

resource "evalguard_eval_schedule" "nightly" {
  project_id = evalguard_project.example.id
  name       = "nightly-regression"
  dataset_id = "ds_checkout_golden"
  model      = "gpt-4o-mini"
  metrics    = ["faithfulness", "answer-relevance"]
  cron       = "0 */6 * * *"

  notification_channels {
    type   = "slack"
    target = "https://hooks.slack.com/services/T000/B000/XXXX"
  }
}

resource "evalguard_gateway_policy" "prod_routing" {
  project_id       = evalguard_project.example.id
  name             = "prod-cost-optimized"
  routing_strategy = "cost_optimized"
  cache_ttl_s      = 300

  targets {
    provider = "anthropic"
    model    = "claude-sonnet-5"
    weight   = 3
  }

  targets {
    provider = "openai"
    model    = "gpt-4o"
    weight   = 1
  }
}

data "evalguard_eval_results" "latest" {
  project_id = evalguard_project.example.id
}

data "evalguard_security_report" "current" {
  project_id = evalguard_project.example.id
}
