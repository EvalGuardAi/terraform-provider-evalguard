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
