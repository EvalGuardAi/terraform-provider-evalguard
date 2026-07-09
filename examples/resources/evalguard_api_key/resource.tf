resource "evalguard_api_key" "ci" {
  org_id = var.evalguard_org_id
  name   = "ci-firewall-check"
  scopes = ["firewall:check"]
}
