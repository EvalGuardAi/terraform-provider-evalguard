resource "evalguard_gateway_policy" "prod_routing" {
  project_id       = evalguard_project.example.id
  name             = "prod-cost-optimized"
  description      = "Cost-optimized routing with failover + semantic cache"
  routing_strategy = "cost_optimized"
  fallback_model   = "gpt-4o-mini"
  timeout_ms       = 30000
  retry_count      = 2
  cache_ttl_s      = 300

  targets {
    provider = "anthropic"
    model    = "claude-sonnet-5"
    weight   = 3
    max_rpm  = 2000
  }

  targets {
    provider = "openai"
    model    = "gpt-4o"
    weight   = 1
    max_rpm  = 1000
  }
}
