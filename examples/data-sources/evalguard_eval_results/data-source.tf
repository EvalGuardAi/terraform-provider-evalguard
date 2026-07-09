data "evalguard_eval_results" "latest" {
  project_id = evalguard_project.example.id
  dataset_id = "ds_checkout_golden"
}

output "sample_count" {
  value = data.evalguard_eval_results.latest.sample_count
}
