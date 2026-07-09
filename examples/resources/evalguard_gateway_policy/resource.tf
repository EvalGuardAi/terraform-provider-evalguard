resource "evalguard_gateway_policy" "deny_external_http" {
  project_id  = evalguard_project.example.id
  name        = "deny-external-http"
  description = "Agents may not call arbitrary external endpoints"
  effect      = "deny"
  priority    = 50

  conditions = jsonencode({
    tools = ["http.get", "http.post"]
  })
}
