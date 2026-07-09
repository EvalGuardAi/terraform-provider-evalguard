terraform {
  required_providers {
    evalguard = {
      source  = "EvalGuardAi/evalguard"
      version = "~> 1.0"
    }
  }
}

# The API key is read from the EVALGUARD_API_KEY environment variable by
# default; set it here only if you are not using the environment variable.
# base_url must be an https:// endpoint (http:// is allowed only for localhost).
provider "evalguard" {
  # api_key  = var.evalguard_api_key
  # base_url = "https://api.evalguard.ai/v1"
}
