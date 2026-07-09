resource "evalguard_project" "example" {
  name        = "checkout-assistant"
  description = "LLM checkout assistant — evals, firewall, and gateway config"
  environment = "production"

  tags = {
    team = "payments"
    tier = "critical"
  }
}
