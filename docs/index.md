---
page_title: "EvalGuard Provider"
description: |-
  Manage EvalGuard projects, API keys, firewall rules, eval schedules, and gateway policies as code.
---

# EvalGuard Provider

The EvalGuard provider manages [EvalGuard](https://evalguard.ai) resources — the
AI evaluation, security, and observability platform — declaratively through its
`/api/v1` surface. Define your projects, scoped API keys, runtime firewall
rules, scheduled evals, and gateway routing policies in Terraform and apply them
like any other infrastructure.

## Example Usage

```terraform
terraform {
  required_providers {
    evalguard = {
      source  = "EvalGuardAi/evalguard"
      version = "~> 1.1"
    }
  }
}

provider "evalguard" {
  # api_key is read from EVALGUARD_API_KEY by default.
}

resource "evalguard_project" "example" {
  org_id = var.evalguard_org_id
  name   = "checkout-assistant"
  slug   = "checkout-assistant"
}
```

## Authentication

The provider authenticates with an EvalGuard API key, supplied either via the
`EVALGUARD_API_KEY` environment variable (recommended) or the `api_key`
argument. Generate a key from **Settings → API Keys** in the EvalGuard
dashboard, or with the `evalguard_api_key` resource.

```shell
export EVALGUARD_API_KEY="eg_..."
```

## Security

- **The `api_key` is marked sensitive** and never printed in plan output or logs.
- **`base_url` must be `https://`.** The API key is sent as a `Bearer` token on
  every request, so the provider rejects a plaintext `http://` endpoint (the one
  exception is `localhost`, for local development against a dev server). This is
  a hard validation error, not a warning.
- Requests to transient failures (HTTP 429, and 5xx on idempotent reads) are
  retried with exponential backoff; a `POST` (create) is never retried on 5xx,
  to avoid duplicating a resource the server may have already committed.

## Schema

### Optional

- `api_key` (String, Sensitive) API key for authenticating with the EvalGuard API. Defaults to the `EVALGUARD_API_KEY` environment variable.
- `base_url` (String) Base URL for the EvalGuard API. Must be an `https://` endpoint (`http://` is permitted only for localhost). Defaults to `https://evalguard.ai/api/v1`.
