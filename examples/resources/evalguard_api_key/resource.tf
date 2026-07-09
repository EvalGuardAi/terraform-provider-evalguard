resource "evalguard_api_key" "ci" {
  project_id = evalguard_project.example.id
  name       = "ci-pipeline"
  scopes     = ["eval:read", "eval:write", "security:scan"]
  expires_at = "2027-01-01T00:00:00Z"
}

# The generated key is returned once; store it securely. Only the first 8
# characters are retained in state (key_preview, marked sensitive).
output "api_key_preview" {
  value = evalguard_api_key.ci.key_preview
}
