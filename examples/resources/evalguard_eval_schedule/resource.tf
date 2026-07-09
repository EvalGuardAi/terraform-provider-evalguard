resource "evalguard_eval_schedule" "nightly" {
  project_id      = evalguard_project.example.id
  name            = "nightly-regression"
  cron_expression = "0 3 * * *"
  enabled         = true

  config = jsonencode({
    model   = "gpt-4"
    scorers = ["exact-match", "faithfulness"]
  })
}
