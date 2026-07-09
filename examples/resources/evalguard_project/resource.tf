resource "evalguard_project" "example" {
  org_id = var.evalguard_org_id
  name   = "checkout-assistant"
  slug   = "checkout-assistant"

  settings = jsonencode({
    retention_days = 30
  })
}
