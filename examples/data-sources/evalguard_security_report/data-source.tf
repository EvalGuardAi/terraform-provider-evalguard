data "evalguard_security_report" "current" {
  project_id = evalguard_project.example.id
}

output "critical_findings" {
  value = data.evalguard_security_report.current.critical_count
}
