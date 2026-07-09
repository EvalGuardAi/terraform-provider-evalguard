// Terraform provider for EvalGuard.
//
// Each resource below executes real HTTP CRUD against the EvalGuard /api/v1
// surface via the `httpDo` helper. Read paths surface 404s as state-clear (so
// an out-of-band delete causes a re-create on the next apply instead of an
// error loop), and every mutating request carries the
// `x-requested-with: terraform-provider` header required by
// `createApiHandler`'s CSRF gate.
//
// v1.1.0 realigned every request body with the API's actual contract. v1.0.0
// had been written against an imagined API — camelCase vs snake_case, nested
// vs flat, and a `project` create that omitted the required `slug`/`orgId` —
// and its unit tests passed only because they exercised an httptest mock that
// impersonated that imagined shape. `TestContract*` in main_test.go now pins
// each request body to the schema the server actually validates.
//
// Resources (5):
//   - evalguard_project          POST /projects · GET|PATCH|DELETE /projects/{id}
//   - evalguard_api_key          POST /api-keys · GET /api-keys?orgId · DELETE /api-keys/{id}
//   - evalguard_firewall_rule    POST /firewall/rules (upsert) · GET ?projectId · DELETE ?ruleId&projectId
//   - evalguard_eval_schedule    POST /eval-schedules · GET ?projectId · PATCH · DELETE ?id
//   - evalguard_gateway_policy   POST /gateway/policies (action=create-rule) · GET ?projectId · DELETE ?id
//
// Data sources: none. The two that shipped in v1.0.0 had no-op Read functions
// and were removed in v1.1.0.
//
// 15 additional resources (scorer, dataset, member, team, provider_key,
// audit_destination, alert, compliance_framework_subscription, eval_run,
// role, vault_config, mcp_server, mcp_tool_permission, persona,
// red_team_config) were previously declared as schema-only stubs. They
// have been removed from this binary until each gets a real HTTP wiring
// — better to ship 5 working resources than 20 that promise CRUD but
// no-op silently. Track the rollout in
// `packages/terraform-provider/ROADMAP.md`.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

// version is injected at release time by GoReleaser (-ldflags "-X main.version=...").
// It defaults to "dev" for local builds and is surfaced in the User-Agent so the
// API can attribute traffic and we can correlate issues to a provider release.
var version = "dev"

// httpRetryMax bounds the transient-error retry loop in httpDo.
const httpRetryMax = 3

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: Provider,
	})
}

// validateHTTPSURL is the base_url schema validator: the URL must be a
// well-formed absolute https:// endpoint. Rejecting plaintext http:// is a
// security control — the API key travels as a Bearer token on every request,
// so a plaintext base_url would leak the credential to any network observer.
// A localhost http URL is permitted only for provider development/testing.
func validateHTTPSURL(v interface{}, path cty.Path) diag.Diagnostics {
	raw, _ := v.(string)
	u, err := url.Parse(raw)
	if err != nil {
		return diag.Errorf("base_url is not a valid URL: %v", err)
	}
	if u.Host == "" || !u.IsAbs() {
		return diag.Errorf("base_url must be an absolute URL (got %q)", raw)
	}
	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	isHTTPS := u.Scheme == "https"
	isLocalHTTP := u.Scheme == "http" && isLocal
	if !isHTTPS && !isLocalHTTP {
		return diag.Errorf(
			"base_url must use https:// (got %q) — a plaintext URL would leak the API key sent as a Bearer token on every request; http:// is allowed only for localhost",
			raw,
		)
	}
	return nil
}

// Provider returns the EvalGuard Terraform provider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("EVALGUARD_API_KEY", nil),
				Description: "API key for authenticating with the EvalGuard API.",
			},
			"base_url": {
				Type:             schema.TypeString,
				Optional:         true,
				Default:          "https://evalguard.ai/api/v1",
				Description:      "Base URL for the EvalGuard API. Must be an https:// endpoint (http:// is permitted only for localhost).",
				ValidateDiagFunc: validateHTTPSURL,
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			// Five resources, each wired to real /api/v1 CRUD. New resources
			// land here only after their HTTP path has been implemented (see
			// the `resource<Name>{Create,Read,Update,Delete}` functions below)
			// AND an integration test against a httptest mock has shipped.
			"evalguard_project":        resourceProject(),
			"evalguard_api_key":        resourceAPIKey(),
			"evalguard_firewall_rule":  resourceFirewallRule(),
			"evalguard_eval_schedule":  resourceEvalSchedule(),
			"evalguard_gateway_policy": resourceGatewayPolicy(),
		},
		// No data sources. `evalguard_eval_results` and `evalguard_security_report`
		// shipped in v1.0.0 with no-op Read functions — they declared a schema and
		// returned nothing, so every attribute silently resolved to its zero value.
		// They were removed in v1.1.0 rather than left as decoration; they will
		// return once backed by a real API read.
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: providerConfigure,
	}
}

type apiClient struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

func providerConfigure(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	apiKey := d.Get("api_key").(string)
	baseURL := d.Get("base_url").(string)

	// Defense in depth: re-assert the https requirement at configure time. The
	// schema validator already guards typed input, but base_url can also arrive
	// via the EVALGUARD_API_KEY-style default/env path, and a leaked Bearer
	// token over plaintext is a credential-disclosure bug, not a style nit.
	if diags := validateHTTPSURL(baseURL, cty.Path{}); diags.HasError() {
		return nil, diags
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, diag.Errorf("api_key must not be empty (set it on the provider block or via the EVALGUARD_API_KEY environment variable)")
	}

	return &apiClient{
		apiKey:  apiKey,
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// ──────────────────────────────────────────────
// HTTP helper (D5 2026-05-19 — replaces the previous stub CRUD)
//
// httpDo executes an authenticated request against the EvalGuard API,
// JSON-encoding `body` if provided and JSON-decoding the response into
// `out` if provided. Returns a non-nil error on non-2xx, transport, or
// JSON failures. 404 is wrapped in `apiNotFoundError` so Read paths
// can clear state cleanly when the resource was deleted out-of-band.
//
// All EvalGuard /api/v1 routes return the standard `{success, data}`
// envelope; `out` is unmarshalled from the `data` field via unwrap().
// ──────────────────────────────────────────────

type apiNotFoundError struct {
	resource string
	id       string
}

func (e *apiNotFoundError) Error() string {
	return fmt.Sprintf("%s %q not found", e.resource, e.id)
}

// idempotentMethod reports whether re-sending a request is safe. A 5xx or a
// dropped connection leaves a POST (create) ambiguous — the server may have
// committed before failing to respond — so those are retried only for
// naturally idempotent verbs. 429 is always safe to retry (the server
// explicitly declined to process the request).
func idempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead:
		return true
	default:
		return false
	}
}

// sleepBackoff waits an exponential backoff (250ms · 2^attempt, capped at 5s)
// or returns false if the context is cancelled first.
func sleepBackoff(ctx context.Context, attempt int) bool {
	d := time.Duration(math.Min(
		float64(250*time.Millisecond)*math.Pow(2, float64(attempt)),
		float64(5*time.Second),
	))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func httpDo(ctx context.Context, c *apiClient, method, path string, body interface{}, out interface{}) error {
	var buf []byte
	if body != nil {
		var err error
		buf, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
	}

	var respBytes []byte
	var status int
	for attempt := 0; ; attempt++ {
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(buf)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("User-Agent", "terraform-provider-evalguard/"+version)
		// Required by createApiHandler's CSRF protection on mutating methods.
		req.Header.Set("x-requested-with", "terraform-provider")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		res, err := c.http.Do(req)
		if err != nil {
			// Transient transport error: retry only for idempotent verbs, and
			// only while the context is still live.
			if idempotentMethod(method) && attempt < httpRetryMax && ctx.Err() == nil {
				if sleepBackoff(ctx, attempt) {
					continue
				}
			}
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		respBytes, _ = io.ReadAll(res.Body)
		status = res.StatusCode
		_ = res.Body.Close()

		// 429 is always retry-safe; 5xx only for idempotent verbs (a retried
		// POST could double-create). 4xx (other than 429) is terminal.
		retryable := status == http.StatusTooManyRequests ||
			(status >= 500 && idempotentMethod(method))
		if retryable && attempt < httpRetryMax && ctx.Err() == nil {
			if sleepBackoff(ctx, attempt) {
				continue
			}
		}
		break
	}

	if status == http.StatusNotFound {
		return &apiNotFoundError{resource: path, id: ""}
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("evalguard API %s %s returned %d: %s",
			method, path, status, truncate(string(respBytes), 500))
	}
	if out != nil && len(respBytes) > 0 {
		data, err := unwrap(respBytes)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}
	}
	return nil
}

// apiEnvelope mirrors the {success, data, error} shape every
// /api/v1 route returns.
type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

func unwrap(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	var env apiEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		// Not enveloped → return raw.
		return b, nil
	}
	if env.Error != nil {
		return nil, fmt.Errorf("evalguard API error %s: %s", env.Error.Code, env.Error.Message)
	}
	if len(env.Data) > 0 {
		return env.Data, nil
	}
	return b, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// isNotFound checks if an error from httpDo is the typed 404 marker.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nf *apiNotFoundError
	return errors.As(err, &nf)
}

// ──────────────────────────────────────────────
// ──────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────

// jsonObjectString validates that a schema field holds a JSON object. Several
// EvalGuard fields (`condition`, `action`, `config`, `conditions`) are free-form
// JSON on the server; Terraform has no native "any JSON" type, so users pass
// `jsonencode({...})` and we validate + decode here rather than shipping a
// lossy flattened map.
func jsonObjectString(v interface{}, path cty.Path) diag.Diagnostics {
	raw, _ := v.(string)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var probe map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return diag.Errorf("must be a JSON object (use jsonencode({...})): %v", err)
	}
	return nil
}

// decodeJSONObject turns a jsonencode()'d schema field into a map for the
// request body. An empty string yields an empty object, which is what every
// `.default({})` / `z.record(...)` field on the server expects.
func decodeJSONObject(raw string) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	return out, nil
}

// encodeJSONObject renders a decoded object back to the canonical string form
// Terraform stores in state. Keys are sorted by encoding/json, so a server
// round-trip is stable and does not produce a perpetual diff.
func encodeJSONObject(v map[string]interface{}) (string, error) {
	if len(v) == 0 {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode JSON object: %w", err)
	}
	return string(b), nil
}

func stringList(d *schema.ResourceData, key string) []string {
	raw, ok := d.GetOk(key)
	if !ok {
		return nil
	}
	items := raw.([]interface{})
	out := make([]string, 0, len(items))
	for _, i := range items {
		out = append(out, fmt.Sprintf("%v", i))
	}
	return out
}

// ──────────────────────────────────────────────
// Resource: evalguard_project
//
// POST   /projects           {name, slug, orgId}
// GET    /projects/{id}
// PATCH  /projects/{id}      {name?, slug?, settings?}
// DELETE /projects/{id}
// ──────────────────────────────────────────────

func resourceProject() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an EvalGuard project — the tenant boundary that evals, firewall rules, and gateway policies hang off.",
		CreateContext: resourceProjectCreate,
		ReadContext:   resourceProjectRead,
		UpdateContext: resourceProjectUpdate,
		DeleteContext: resourceProjectDelete,
		Schema: map[string]*schema.Schema{
			"org_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Organization that owns the project. The caller must be a member of it.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Human-readable project name (2–50 characters).",
			},
			"slug": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL-safe identifier, unique within the org: lowercase alphanumeric and hyphens (2–50 characters).",
			},
			"settings": {
				Type:             schema.TypeString,
				Optional:         true,
				ValidateDiagFunc: jsonObjectString,
				Description:      "Free-form project settings as a JSON object, e.g. `jsonencode({ retention_days = 30 })`.",
			},
			"created_at": {Type: schema.TypeString, Computed: true},
			"updated_at": {Type: schema.TypeString, Computed: true},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

// projectAPI mirrors the row returned by /api/v1/projects (snake_case columns,
// straight out of Postgres).
type projectAPI struct {
	ID        string                 `json:"id,omitempty"`
	OrgID     string                 `json:"org_id,omitempty"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Settings  map[string]interface{} `json:"settings,omitempty"`
	CreatedAt string                 `json:"created_at,omitempty"`
	UpdatedAt string                 `json:"updated_at,omitempty"`
}

// createProjectBody is the POST /projects contract: camelCase orgId alongside
// the snake_case row fields. `settings` is not accepted on create.
type createProjectBody struct {
	OrgID string `json:"orgId"`
	Name  string `json:"name"`
	Slug  string `json:"slug"`
}

func projectToState(d *schema.ResourceData, p *projectAPI) error {
	d.SetId(p.ID)
	if err := d.Set("org_id", p.OrgID); err != nil {
		return err
	}
	if err := d.Set("name", p.Name); err != nil {
		return err
	}
	if err := d.Set("slug", p.Slug); err != nil {
		return err
	}
	// Only write `settings` back when the server actually holds some, so an
	// unset field does not flip between "" and "{}" across refreshes.
	if len(p.Settings) > 0 {
		enc, err := encodeJSONObject(p.Settings)
		if err != nil {
			return err
		}
		if err := d.Set("settings", enc); err != nil {
			return err
		}
	}
	if err := d.Set("created_at", p.CreatedAt); err != nil {
		return err
	}
	return d.Set("updated_at", p.UpdatedAt)
}

func resourceProjectCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	body := createProjectBody{
		OrgID: d.Get("org_id").(string),
		Name:  d.Get("name").(string),
		Slug:  d.Get("slug").(string),
	}
	var out projectAPI
	if err := httpDo(ctx, c, http.MethodPost, "/projects", body, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)

	// The create route ignores `settings`; apply it with a follow-up PATCH so
	// the resource converges in one apply.
	if raw, ok := d.GetOk("settings"); ok && strings.TrimSpace(raw.(string)) != "" {
		return resourceProjectUpdate(ctx, d, m)
	}
	return resourceProjectRead(ctx, d, m)
}

func resourceProjectRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out projectAPI
	err := httpDo(ctx, c, http.MethodGet, "/projects/"+url.PathEscape(d.Id()), nil, &out)
	if isNotFound(err) {
		// Deleted out-of-band: drop it from state instead of failing the plan.
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if err := projectToState(d, &out); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceProjectUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)

	// `name` and `slug` are Required, so they are always known; sending them
	// unconditionally makes the PATCH converge regardless of how the diff was
	// computed (and PATCH is idempotent). `settings` only ships when the
	// practitioner actually set it, so we never clobber server-side settings
	// written outside Terraform with an empty object.
	body := map[string]interface{}{
		"name": d.Get("name").(string),
		"slug": d.Get("slug").(string),
	}
	if raw, ok := d.GetOk("settings"); ok && strings.TrimSpace(raw.(string)) != "" {
		settings, err := decodeJSONObject(raw.(string))
		if err != nil {
			return diag.FromErr(err)
		}
		body["settings"] = settings
	}

	var out projectAPI
	if err := httpDo(ctx, c, http.MethodPatch, "/projects/"+url.PathEscape(d.Id()), body, &out); err != nil {
		return diag.FromErr(err)
	}
	return resourceProjectRead(ctx, d, m)
}

func resourceProjectDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	err := httpDo(ctx, c, http.MethodDelete, "/projects/"+url.PathEscape(d.Id()), nil, nil)
	if err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_api_key
//
// POST   /api-keys            {orgId, name, scopes, expiresAt?}  → 201 {..., rawKey}
// GET    /api-keys?orgId=…    (list; filtered client-side by id)
// DELETE /api-keys/{keyId}    (soft revoke)
//
// name/scopes/expires_at are immutable server-side, so a change forces a new
// key. The raw secret is returned exactly once, at creation.
// ──────────────────────────────────────────────

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an EvalGuard platform API key. The secret is readable only at creation time.",
		CreateContext: resourceAPIKeyCreate,
		ReadContext:   resourceAPIKeyRead,
		DeleteContext: resourceAPIKeyDelete,
		Schema: map[string]*schema.Schema{
			"org_id": {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Organization that owns the key."},
			"name":   {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Key name, unique within the org."},
			"scopes": {
				Type:        schema.TypeList,
				Optional:    true,
				ForceNew:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Scopes granted to the key, e.g. `firewall:check`. A key with no scopes is unauthorized for every scoped route.",
			},
			"expires_at": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "RFC 3339 expiry timestamp. Omit for a non-expiring key.",
			},
			"key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The raw API key. Returned only when the key is created; empty after a refresh or import.",
			},
			"key_prefix": {Type: schema.TypeString, Computed: true},
			"revoked":    {Type: schema.TypeBool, Computed: true},
			"created_at": {Type: schema.TypeString, Computed: true},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type apiKeyAPI struct {
	ID        string   `json:"id,omitempty"`
	OrgID     string   `json:"org_id,omitempty"`
	Name      string   `json:"name"`
	KeyPrefix string   `json:"key_prefix,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Revoked   bool     `json:"revoked,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	RawKey    string   `json:"rawKey,omitempty"`
}

type createAPIKeyBody struct {
	OrgID     string   `json:"orgId"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
}

// apiKeyListResponse covers both shapes GET /api-keys returns: a bare array,
// or a paginated {keys, total} object.
type apiKeyListResponse struct {
	Keys  []apiKeyAPI `json:"keys"`
	Total int         `json:"total"`
}

func resourceAPIKeyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	body := createAPIKeyBody{
		OrgID:     d.Get("org_id").(string),
		Name:      d.Get("name").(string),
		Scopes:    stringList(d, "scopes"),
		ExpiresAt: d.Get("expires_at").(string),
	}
	var out apiKeyAPI
	if err := httpDo(ctx, c, http.MethodPost, "/api-keys", body, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)
	// The secret exists in this response only. Persist it now or lose it.
	if err := d.Set("key", out.RawKey); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("key_prefix", out.KeyPrefix); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("created_at", out.CreatedAt); err != nil {
		return diag.FromErr(err)
	}
	return resourceAPIKeyRead(ctx, d, m)
}

func resourceAPIKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)

	// There is no GET /api-keys/{id}; list the org's keys and pick ours out.
	raw := json.RawMessage{}
	err := httpDo(ctx, c, http.MethodGet,
		"/api-keys?orgId="+url.QueryEscape(d.Get("org_id").(string)), nil, &raw)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}

	var keys []apiKeyAPI
	if uerr := json.Unmarshal(raw, &keys); uerr != nil {
		var paged apiKeyListResponse
		if perr := json.Unmarshal(raw, &paged); perr != nil {
			return diag.Errorf("decode api-keys list: %v", uerr)
		}
		keys = paged.Keys
	}

	for _, k := range keys {
		if k.ID != d.Id() {
			continue
		}
		// A revoked key is dead server-side; treat it as gone so the next plan
		// recreates it rather than reporting a working key.
		if k.Revoked {
			d.SetId("")
			return nil
		}
		if err := d.Set("name", k.Name); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("org_id", k.OrgID); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("key_prefix", k.KeyPrefix); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("scopes", k.Scopes); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("revoked", k.Revoked); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("created_at", k.CreatedAt); err != nil {
			return diag.FromErr(err)
		}
		return nil
	}

	d.SetId("")
	return nil
}

func resourceAPIKeyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	err := httpDo(ctx, c, http.MethodDelete, "/api-keys/"+url.PathEscape(d.Id()), nil, nil)
	if err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_firewall_rule
//
// POST   /firewall/rules                       {projectId, rule{…}}  (upsert)
// GET    /firewall/rules?projectId=…           (list; filtered by id)
// DELETE /firewall/rules?ruleId=…&projectId=…
// ──────────────────────────────────────────────

func resourceFirewallRule() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a firewall rule on an EvalGuard project.",
		CreateContext: resourceFirewallRuleCreate,
		ReadContext:   resourceFirewallRuleRead,
		UpdateContext: resourceFirewallRuleUpdate,
		DeleteContext: resourceFirewallRuleDelete,
		Schema: map[string]*schema.Schema{
			"project_id":  {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Project the rule belongs to."},
			"name":        {Type: schema.TypeString, Required: true},
			"type":        {Type: schema.TypeString, Required: true, Description: "Rule type, e.g. `regex`, `semantic`, `pii`."},
			"description": {Type: schema.TypeString, Optional: true},
			"condition": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: jsonObjectString,
				Description:      "Match condition as a JSON object, e.g. `jsonencode({ pattern = \"(?i)ignore previous\" })`.",
			},
			"action": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: jsonObjectString,
				Description:      "Action as a JSON object, e.g. `jsonencode({ type = \"block\" })`.",
			},
			"priority": {Type: schema.TypeInt, Optional: true, Default: 100},
			"enabled":  {Type: schema.TypeBool, Optional: true, Default: true},
			"tags": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"regions": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Jurisdiction tokens the rule applies in (EU, US, APAC, ISO-3166 alpha-2, or GLOBAL). Empty means everywhere.",
			},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type firewallRuleAPI struct {
	ID          string                 `json:"id,omitempty"`
	ProjectID   string                 `json:"project_id,omitempty"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	Condition   map[string]interface{} `json:"condition"`
	Action      map[string]interface{} `json:"action"`
	Priority    int                    `json:"priority,omitempty"`
	Enabled     bool                   `json:"enabled"`
	Tags        []string               `json:"tags,omitempty"`
	Regions     []string               `json:"regions,omitempty"`
}

// upsertFirewallRuleBody is the POST /firewall/rules contract: the rule is
// nested, and the project is identified by a camelCase sibling field.
type upsertFirewallRuleBody struct {
	ProjectID string          `json:"projectId"`
	Rule      firewallRuleAPI `json:"rule"`
}

func firewallRuleFromState(d *schema.ResourceData) (*firewallRuleAPI, error) {
	cond, err := decodeJSONObject(d.Get("condition").(string))
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}
	act, err := decodeJSONObject(d.Get("action").(string))
	if err != nil {
		return nil, fmt.Errorf("action: %w", err)
	}
	r := &firewallRuleAPI{
		ID:          d.Id(),
		Name:        d.Get("name").(string),
		Type:        d.Get("type").(string),
		Description: d.Get("description").(string),
		Condition:   cond,
		Action:      act,
		Priority:    d.Get("priority").(int),
		Enabled:     d.Get("enabled").(bool),
		Tags:        stringList(d, "tags"),
		Regions:     stringList(d, "regions"),
	}
	return r, nil
}

func firewallRuleToState(d *schema.ResourceData, r *firewallRuleAPI) error {
	d.SetId(r.ID)
	cond, err := encodeJSONObject(r.Condition)
	if err != nil {
		return err
	}
	act, err := encodeJSONObject(r.Action)
	if err != nil {
		return err
	}
	fields := map[string]interface{}{
		"name":        r.Name,
		"type":        r.Type,
		"description": r.Description,
		"condition":   cond,
		"action":      act,
		"priority":    r.Priority,
		"enabled":     r.Enabled,
	}
	// GET /firewall/rules projects each row onto FirewallRuleV2, which carries no
	// `project_id`. Writing the zero value here would blank the configured
	// project and force a spurious replacement on the next plan.
	if r.ProjectID != "" {
		fields["project_id"] = r.ProjectID
	}
	for k, v := range fields {
		if err := d.Set(k, v); err != nil {
			return err
		}
	}
	if len(r.Tags) > 0 {
		if err := d.Set("tags", r.Tags); err != nil {
			return err
		}
	}
	if len(r.Regions) > 0 {
		if err := d.Set("regions", r.Regions); err != nil {
			return err
		}
	}
	return nil
}

// upsertFirewallRule backs both Create and Update — the server route is an
// upsert keyed on rule.id (absent on create, present on update).
func upsertFirewallRule(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	rule, err := firewallRuleFromState(d)
	if err != nil {
		return diag.FromErr(err)
	}
	body := upsertFirewallRuleBody{ProjectID: d.Get("project_id").(string), Rule: *rule}

	var out firewallRuleAPI
	if err := httpDo(ctx, c, http.MethodPost, "/firewall/rules", body, &out); err != nil {
		return diag.FromErr(err)
	}
	if out.ID != "" {
		d.SetId(out.ID)
	}
	return resourceFirewallRuleRead(ctx, d, m)
}

func resourceFirewallRuleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return upsertFirewallRule(ctx, d, m)
}

func resourceFirewallRuleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return upsertFirewallRule(ctx, d, m)
}

func resourceFirewallRuleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var rules []firewallRuleAPI
	err := httpDo(ctx, c, http.MethodGet,
		"/firewall/rules?projectId="+url.QueryEscape(d.Get("project_id").(string)), nil, &rules)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for i := range rules {
		if rules[i].ID == d.Id() {
			if err := firewallRuleToState(d, &rules[i]); err != nil {
				return diag.FromErr(err)
			}
			return nil
		}
	}
	d.SetId("")
	return nil
}

func resourceFirewallRuleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	path := fmt.Sprintf("/firewall/rules?ruleId=%s&projectId=%s",
		url.QueryEscape(d.Id()), url.QueryEscape(d.Get("project_id").(string)))
	if err := httpDo(ctx, c, http.MethodDelete, path, nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_eval_schedule
//
// POST   /eval-schedules              {projectId, name, cronExpression, config, …}
// GET    /eval-schedules?projectId=…  (list; filtered by id)
// PATCH  /eval-schedules              {id, …}
// DELETE /eval-schedules?id=…
// ──────────────────────────────────────────────

func resourceEvalSchedule() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a recurring evaluation schedule on an EvalGuard project.",
		CreateContext: resourceEvalScheduleCreate,
		ReadContext:   resourceEvalScheduleRead,
		UpdateContext: resourceEvalScheduleUpdate,
		DeleteContext: resourceEvalScheduleDelete,
		Schema: map[string]*schema.Schema{
			"project_id": {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":       {Type: schema.TypeString, Required: true},
			"cron_expression": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Cron expression controlling when the eval runs, e.g. `0 3 * * *`.",
			},
			"config": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: jsonObjectString,
				Description:      "Eval configuration as a JSON object, e.g. `jsonencode({ model = \"gpt-4\", scorers = [\"exact-match\"] })`.",
			},
			"description": {Type: schema.TypeString, Optional: true},
			"dataset_id":  {Type: schema.TypeString, Optional: true},
			"enabled":     {Type: schema.TypeBool, Optional: true, Default: true},
			"next_run_at": {Type: schema.TypeString, Computed: true},
			"created_at":  {Type: schema.TypeString, Computed: true},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type evalScheduleAPI struct {
	ID             string                 `json:"id,omitempty"`
	ProjectID      string                 `json:"project_id,omitempty"`
	Name           string                 `json:"name"`
	CronExpression string                 `json:"cron_expression,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty"`
	Description    string                 `json:"description,omitempty"`
	DatasetID      string                 `json:"dataset_id,omitempty"`
	Enabled        bool                   `json:"enabled"`
	NextRunAt      string                 `json:"next_run_at,omitempty"`
	CreatedAt      string                 `json:"created_at,omitempty"`
}

func evalScheduleToState(d *schema.ResourceData, s *evalScheduleAPI) error {
	d.SetId(s.ID)
	cfg, err := encodeJSONObject(s.Config)
	if err != nil {
		return err
	}
	fields := map[string]interface{}{
		"name":            s.Name,
		"cron_expression": s.CronExpression,
		"description":     s.Description,
		"dataset_id":      s.DatasetID,
		"enabled":         s.Enabled,
		"next_run_at":     s.NextRunAt,
		"created_at":      s.CreatedAt,
	}
	if cfg != "" {
		fields["config"] = cfg
	}
	// Never blank a configured project_id if the server omits it from the row.
	if s.ProjectID != "" {
		fields["project_id"] = s.ProjectID
	}
	for k, v := range fields {
		if err := d.Set(k, v); err != nil {
			return err
		}
	}
	return nil
}

func resourceEvalScheduleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	cfg, err := decodeJSONObject(d.Get("config").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	body := map[string]interface{}{
		"projectId":      d.Get("project_id").(string),
		"name":           d.Get("name").(string),
		"cronExpression": d.Get("cron_expression").(string),
		"config":         cfg,
	}
	if v, ok := d.GetOk("description"); ok {
		body["description"] = v.(string)
	}
	if v, ok := d.GetOk("dataset_id"); ok {
		body["datasetId"] = v.(string)
	}

	var out evalScheduleAPI
	if err := httpDo(ctx, c, http.MethodPost, "/eval-schedules", body, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)
	return resourceEvalScheduleRead(ctx, d, m)
}

func resourceEvalScheduleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var schedules []evalScheduleAPI
	err := httpDo(ctx, c, http.MethodGet,
		"/eval-schedules?projectId="+url.QueryEscape(d.Get("project_id").(string)), nil, &schedules)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for i := range schedules {
		if schedules[i].ID == d.Id() {
			if err := evalScheduleToState(d, &schedules[i]); err != nil {
				return diag.FromErr(err)
			}
			return nil
		}
	}
	d.SetId("")
	return nil
}

func resourceEvalScheduleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	body := map[string]interface{}{"id": d.Id()}
	if d.HasChange("name") {
		body["name"] = d.Get("name").(string)
	}
	if d.HasChange("cron_expression") {
		body["cronExpression"] = d.Get("cron_expression").(string)
	}
	if d.HasChange("description") {
		body["description"] = d.Get("description").(string)
	}
	if d.HasChange("enabled") {
		body["enabled"] = d.Get("enabled").(bool)
	}
	if d.HasChange("dataset_id") {
		body["datasetId"] = d.Get("dataset_id").(string)
	}
	if d.HasChange("config") {
		cfg, err := decodeJSONObject(d.Get("config").(string))
		if err != nil {
			return diag.FromErr(err)
		}
		body["config"] = cfg
	}
	if len(body) == 1 {
		return resourceEvalScheduleRead(ctx, d, m)
	}
	if err := httpDo(ctx, c, http.MethodPatch, "/eval-schedules", body, nil); err != nil {
		return diag.FromErr(err)
	}
	return resourceEvalScheduleRead(ctx, d, m)
}

func resourceEvalScheduleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	err := httpDo(ctx, c, http.MethodDelete, "/eval-schedules?id="+url.QueryEscape(d.Id()), nil, nil)
	if err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_gateway_policy
//
// POST   /gateway/policies   {action:"create-rule", projectId, rule{…}}
// GET    /gateway/policies?projectId=…   → {rules, appliedTemplates}
// DELETE /gateway/policies?id=…
//
// The server exposes no update verb for a policy rule, so every attribute is
// ForceNew: Terraform replaces the rule instead of silently drifting.
// ──────────────────────────────────────────────

func resourceGatewayPolicy() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an agent gateway policy rule (allow/deny) on an EvalGuard project.",
		CreateContext: resourceGatewayPolicyCreate,
		ReadContext:   resourceGatewayPolicyRead,
		DeleteContext: resourceGatewayPolicyDelete,
		Schema: map[string]*schema.Schema{
			"project_id":  {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":        {Type: schema.TypeString, Required: true, ForceNew: true},
			"description": {Type: schema.TypeString, Optional: true, ForceNew: true},
			"effect": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Either `allow` or `deny`.",
			},
			"priority": {Type: schema.TypeInt, Optional: true, Default: 100, ForceNew: true},
			"conditions": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ValidateDiagFunc: jsonObjectString,
				Description:      "Match conditions as a JSON object, e.g. `jsonencode({ tools = [\"http.get\"] })`.",
			},
			"created_at": {Type: schema.TypeString, Computed: true},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type gatewayPolicyAPI struct {
	ID          string                 `json:"id,omitempty"`
	ProjectID   string                 `json:"project_id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Priority    int                    `json:"priority,omitempty"`
	Effect      string                 `json:"effect"`
	Conditions  map[string]interface{} `json:"conditions,omitempty"`
	CreatedAt   string                 `json:"created_at,omitempty"`
}

type createGatewayPolicyBody struct {
	Action    string                 `json:"action"`
	ProjectID string                 `json:"projectId"`
	Rule      gatewayPolicyRuleInput `json:"rule"`
}

type gatewayPolicyRuleInput struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Priority    int                    `json:"priority"`
	Effect      string                 `json:"effect"`
	Conditions  map[string]interface{} `json:"conditions"`
}

// createGatewayPolicyResponse mirrors the 201 body: {rule: {...}}.
type createGatewayPolicyResponse struct {
	Rule gatewayPolicyAPI `json:"rule"`
}

// gatewayPolicyListResponse mirrors GET: {rules: [...], appliedTemplates: [...]}.
type gatewayPolicyListResponse struct {
	Rules []gatewayPolicyAPI `json:"rules"`
}

func gatewayPolicyToState(d *schema.ResourceData, p *gatewayPolicyAPI) error {
	d.SetId(p.ID)
	conds, err := encodeJSONObject(p.Conditions)
	if err != nil {
		return err
	}
	fields := map[string]interface{}{
		"name":        p.Name,
		"description": p.Description,
		"effect":      p.Effect,
		"priority":    p.Priority,
		"created_at":  p.CreatedAt,
	}
	if conds != "" {
		fields["conditions"] = conds
	}
	// Never blank a configured project_id if the server omits it from the row.
	if p.ProjectID != "" {
		fields["project_id"] = p.ProjectID
	}
	for k, v := range fields {
		if err := d.Set(k, v); err != nil {
			return err
		}
	}
	return nil
}

func resourceGatewayPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	conds, err := decodeJSONObject(d.Get("conditions").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	body := createGatewayPolicyBody{
		Action:    "create-rule",
		ProjectID: d.Get("project_id").(string),
		Rule: gatewayPolicyRuleInput{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			Priority:    d.Get("priority").(int),
			Effect:      d.Get("effect").(string),
			Conditions:  conds,
		},
	}
	var out createGatewayPolicyResponse
	if err := httpDo(ctx, c, http.MethodPost, "/gateway/policies", body, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.Rule.ID)
	return resourceGatewayPolicyRead(ctx, d, m)
}

func resourceGatewayPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out gatewayPolicyListResponse
	err := httpDo(ctx, c, http.MethodGet,
		"/gateway/policies?projectId="+url.QueryEscape(d.Get("project_id").(string)), nil, &out)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for i := range out.Rules {
		if out.Rules[i].ID == d.Id() {
			if err := gatewayPolicyToState(d, &out.Rules[i]); err != nil {
				return diag.FromErr(err)
			}
			return nil
		}
	}
	d.SetId("")
	return nil
}

func resourceGatewayPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	err := httpDo(ctx, c, http.MethodDelete, "/gateway/policies?id="+url.QueryEscape(d.Id()), nil, nil)
	if err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
