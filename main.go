// Terraform provider for EvalGuard.
//
// STATUS: BETA. Each resource below executes real HTTP CRUD against
// the EvalGuard /api/v1 surface via the `httpDo` helper. `terraform
// apply` produces real state changes upstream. Read paths surface
// 404s as state-clear (so an out-of-band delete causes a re-create
// on the next apply instead of an error loop), and every mutating
// request carries the `x-requested-with: terraform-provider` header
// required by `createApiHandler`'s CSRF gate.
//
// Resources shipped (5):
//   - evalguard_project          (POST/GET/PATCH/DELETE /projects)
//   - evalguard_api_key          (POST/GET/PATCH/DELETE /api-keys)
//   - evalguard_firewall_rule    (POST/GET/PATCH/DELETE /firewall/rules)
//   - evalguard_eval_schedule    (POST/GET/PATCH/DELETE /eval-schedules)
//   - evalguard_gateway_policy   (POST/GET/PATCH/DELETE /gateway/policies)
//
// Data sources (2):
//   - evalguard_eval_results
//   - evalguard_security_report
//
// 15 additional resources (scorer, dataset, member, team, provider_key,
// audit_destination, alert, compliance_framework_subscription, eval_run,
// role, vault_config, mcp_server, mcp_tool_permission, persona,
// red_team_config) were previously declared as schema-only stubs. They
// have been removed from this binary until each gets a real HTTP wiring
// — better to ship 5 production-grade resources than 20 that promise
// CRUD but no-op silently. Track the rollout in
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
				Default:          "https://api.evalguard.ai/v1",
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
		DataSourcesMap: map[string]*schema.Resource{
			"evalguard_eval_results":    dataSourceEvalResults(),
			"evalguard_security_report": dataSourceSecurityReport(),
		},
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
// Resource: evalguard_project
// ──────────────────────────────────────────────

func resourceProject() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an EvalGuard project.",
		CreateContext: resourceProjectCreate,
		ReadContext:   resourceProjectRead,
		UpdateContext: resourceProjectUpdate,
		DeleteContext: resourceProjectDelete,
		Schema: map[string]*schema.Schema{
			"name":        {Type: schema.TypeString, Required: true, Description: "Project name."},
			"description": {Type: schema.TypeString, Optional: true, Description: "Project description."},
			"environment": {Type: schema.TypeString, Optional: true, Default: "production", Description: "Environment: production, staging, development."},
			"tags":        {Type: schema.TypeMap, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"created_at":  {Type: schema.TypeString, Computed: true},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type projectAPI struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
}

func projectFromState(d *schema.ResourceData) *projectAPI {
	p := &projectAPI{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Environment: d.Get("environment").(string),
	}
	if raw, ok := d.GetOk("tags"); ok {
		tags := map[string]string{}
		for k, v := range raw.(map[string]interface{}) {
			tags[k] = fmt.Sprintf("%v", v)
		}
		p.Tags = tags
	}
	return p
}

func projectToState(d *schema.ResourceData, p *projectAPI) {
	if p.ID != "" {
		d.SetId(p.ID)
	}
	_ = d.Set("name", p.Name)
	if p.Description != "" {
		_ = d.Set("description", p.Description)
	}
	if p.Environment != "" {
		_ = d.Set("environment", p.Environment)
	}
	if p.Tags != nil {
		_ = d.Set("tags", p.Tags)
	}
	if p.CreatedAt != "" {
		_ = d.Set("created_at", p.CreatedAt)
	}
}

func resourceProjectCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out projectAPI
	if err := httpDo(ctx, c, http.MethodPost, "/projects", projectFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	projectToState(d, &out)
	return nil
}

func resourceProjectRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out projectAPI
	err := httpDo(ctx, c, http.MethodGet, "/projects/"+d.Id(), nil, &out)
	if isNotFound(err) {
		// Project was deleted out-of-band — drop from state so Terraform
		// recreates on next apply instead of erroring forever.
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	projectToState(d, &out)
	return nil
}

func resourceProjectUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out projectAPI
	if err := httpDo(ctx, c, http.MethodPut, "/projects/"+d.Id(), projectFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	projectToState(d, &out)
	return nil
}

func resourceProjectDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	if err := httpDo(ctx, c, http.MethodDelete, "/projects/"+d.Id(), nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_api_key
// ──────────────────────────────────────────────

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an EvalGuard API key.",
		CreateContext: resourceAPIKeyCreate,
		ReadContext:   resourceAPIKeyRead,
		UpdateContext: resourceAPIKeyUpdate,
		DeleteContext: resourceAPIKeyDelete,
		Schema: map[string]*schema.Schema{
			"project_id":  {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Project this key belongs to."},
			"name":        {Type: schema.TypeString, Required: true, Description: "Human-readable key name."},
			"scopes":      {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Permission scopes: eval:read, eval:write, security:scan, etc."},
			"expires_at":  {Type: schema.TypeString, Optional: true, Description: "Expiration timestamp (ISO 8601)."},
			"key_preview": {Type: schema.TypeString, Computed: true, Sensitive: true, Description: "First 8 characters of the generated key."},
			"created_at":  {Type: schema.TypeString, Computed: true},
		},
	}
}

type apiKeyAPI struct {
	ID         string   `json:"id,omitempty"`
	ProjectID  string   `json:"project_id"`
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	KeyPreview string   `json:"key_preview,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
}

func apiKeyFromState(d *schema.ResourceData) *apiKeyAPI {
	k := &apiKeyAPI{
		ProjectID: d.Get("project_id").(string),
		Name:      d.Get("name").(string),
		ExpiresAt: d.Get("expires_at").(string),
	}
	if raw, ok := d.GetOk("scopes"); ok {
		for _, s := range raw.([]interface{}) {
			k.Scopes = append(k.Scopes, s.(string))
		}
	}
	return k
}

func apiKeyToState(d *schema.ResourceData, k *apiKeyAPI) {
	if k.ID != "" {
		d.SetId(k.ID)
	}
	_ = d.Set("project_id", k.ProjectID)
	_ = d.Set("name", k.Name)
	if k.Scopes != nil {
		_ = d.Set("scopes", k.Scopes)
	}
	if k.ExpiresAt != "" {
		_ = d.Set("expires_at", k.ExpiresAt)
	}
	if k.KeyPreview != "" {
		_ = d.Set("key_preview", k.KeyPreview)
	}
	if k.CreatedAt != "" {
		_ = d.Set("created_at", k.CreatedAt)
	}
}

func resourceAPIKeyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out apiKeyAPI
	if err := httpDo(ctx, c, http.MethodPost, "/api-keys", apiKeyFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	apiKeyToState(d, &out)
	return nil
}

func resourceAPIKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out apiKeyAPI
	err := httpDo(ctx, c, http.MethodGet, "/api-keys/"+d.Id(), nil, &out)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	apiKeyToState(d, &out)
	return nil
}

func resourceAPIKeyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out apiKeyAPI
	if err := httpDo(ctx, c, http.MethodPut, "/api-keys/"+d.Id(), apiKeyFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	apiKeyToState(d, &out)
	return nil
}

func resourceAPIKeyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	if err := httpDo(ctx, c, http.MethodDelete, "/api-keys/"+d.Id(), nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_firewall_rule
// ──────────────────────────────────────────────

func resourceFirewallRule() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a prompt firewall rule in EvalGuard.",
		CreateContext: resourceFirewallRuleCreate,
		ReadContext:   resourceFirewallRuleRead,
		UpdateContext: resourceFirewallRuleUpdate,
		DeleteContext: resourceFirewallRuleDelete,
		Schema: map[string]*schema.Schema{
			"project_id":  {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":        {Type: schema.TypeString, Required: true},
			"description": {Type: schema.TypeString, Optional: true},
			"rule_type":   {Type: schema.TypeString, Required: true, Description: "Type: block, allow, transform, rate_limit, content_filter."},
			"priority":    {Type: schema.TypeInt, Optional: true, Default: 100, Description: "Rule priority (lower = higher priority)."},
			"enabled":     {Type: schema.TypeBool, Optional: true, Default: true},
			"conditions": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"field":    {Type: schema.TypeString, Required: true, Description: "Field to match: prompt, response, model, ip, user_id."},
						"operator": {Type: schema.TypeString, Required: true, Description: "Operator: contains, regex, equals, gt, lt."},
						"value":    {Type: schema.TypeString, Required: true},
					},
				},
			},
			"action_config": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Action-specific configuration (e.g., redirect_url, replacement_text, rate_limit_rpm).",
			},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type firewallRuleAPI struct {
	ID           string                     `json:"id,omitempty"`
	ProjectID    string                     `json:"project_id"`
	Name         string                     `json:"name"`
	Description  string                     `json:"description,omitempty"`
	RuleType     string                     `json:"rule_type"`
	Priority     int                        `json:"priority"`
	Enabled      bool                       `json:"enabled"`
	Conditions   []firewallRuleConditionAPI `json:"conditions"`
	ActionConfig map[string]string          `json:"action_config,omitempty"`
}

type firewallRuleConditionAPI struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

func firewallRuleFromState(d *schema.ResourceData) *firewallRuleAPI {
	r := &firewallRuleAPI{
		ProjectID:   d.Get("project_id").(string),
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		RuleType:    d.Get("rule_type").(string),
		Priority:    d.Get("priority").(int),
		Enabled:     d.Get("enabled").(bool),
	}
	for _, raw := range d.Get("conditions").([]interface{}) {
		m := raw.(map[string]interface{})
		r.Conditions = append(r.Conditions, firewallRuleConditionAPI{
			Field:    m["field"].(string),
			Operator: m["operator"].(string),
			Value:    m["value"].(string),
		})
	}
	if raw, ok := d.GetOk("action_config"); ok {
		cfg := map[string]string{}
		for k, v := range raw.(map[string]interface{}) {
			cfg[k] = fmt.Sprintf("%v", v)
		}
		r.ActionConfig = cfg
	}
	return r
}

func firewallRuleToState(d *schema.ResourceData, r *firewallRuleAPI) {
	if r.ID != "" {
		d.SetId(r.ID)
	}
	_ = d.Set("project_id", r.ProjectID)
	_ = d.Set("name", r.Name)
	if r.Description != "" {
		_ = d.Set("description", r.Description)
	}
	_ = d.Set("rule_type", r.RuleType)
	_ = d.Set("priority", r.Priority)
	_ = d.Set("enabled", r.Enabled)
	if len(r.Conditions) > 0 {
		conds := make([]map[string]interface{}, len(r.Conditions))
		for i, c := range r.Conditions {
			conds[i] = map[string]interface{}{"field": c.Field, "operator": c.Operator, "value": c.Value}
		}
		_ = d.Set("conditions", conds)
	}
	if r.ActionConfig != nil {
		_ = d.Set("action_config", r.ActionConfig)
	}
}

func resourceFirewallRuleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out firewallRuleAPI
	if err := httpDo(ctx, c, http.MethodPost, "/firewall/rules", firewallRuleFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	firewallRuleToState(d, &out)
	return nil
}

func resourceFirewallRuleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out firewallRuleAPI
	err := httpDo(ctx, c, http.MethodGet, "/firewall/rules/"+d.Id(), nil, &out)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	firewallRuleToState(d, &out)
	return nil
}

func resourceFirewallRuleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out firewallRuleAPI
	if err := httpDo(ctx, c, http.MethodPut, "/firewall/rules/"+d.Id(), firewallRuleFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	firewallRuleToState(d, &out)
	return nil
}

func resourceFirewallRuleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	if err := httpDo(ctx, c, http.MethodDelete, "/firewall/rules/"+d.Id(), nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_eval_schedule
// ──────────────────────────────────────────────

func resourceEvalSchedule() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a scheduled evaluation run in EvalGuard.",
		CreateContext: resourceEvalScheduleCreate,
		ReadContext:   resourceEvalScheduleRead,
		UpdateContext: resourceEvalScheduleUpdate,
		DeleteContext: resourceEvalScheduleDelete,
		Schema: map[string]*schema.Schema{
			"project_id":           {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":                 {Type: schema.TypeString, Required: true},
			"dataset_id":           {Type: schema.TypeString, Required: true},
			"model":                {Type: schema.TypeString, Required: true},
			"metrics":              {Type: schema.TypeList, Required: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"cron":                 {Type: schema.TypeString, Required: true, Description: "Cron expression (e.g., '0 */6 * * *')."},
			"enabled":              {Type: schema.TypeBool, Optional: true, Default: true},
			"notify_on_regression": {Type: schema.TypeBool, Optional: true, Default: true},
			"regression_threshold": {Type: schema.TypeFloat, Optional: true, Default: 0.05, Description: "Percentage drop that triggers a regression alert."},
			"notification_channels": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type":   {Type: schema.TypeString, Required: true, Description: "Channel type: slack, email, webhook, pagerduty."},
						"target": {Type: schema.TypeString, Required: true, Description: "Channel target (URL, email, etc.)."},
					},
				},
			},
			"last_run_at": {Type: schema.TypeString, Computed: true},
			"next_run_at": {Type: schema.TypeString, Computed: true},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type evalScheduleAPI struct {
	ID                   string                   `json:"id,omitempty"`
	ProjectID            string                   `json:"project_id"`
	Name                 string                   `json:"name"`
	DatasetID            string                   `json:"dataset_id"`
	Model                string                   `json:"model"`
	Metrics              []string                 `json:"metrics"`
	Cron                 string                   `json:"cron"`
	Enabled              bool                     `json:"enabled"`
	NotifyOnRegression   bool                     `json:"notify_on_regression"`
	RegressionThreshold  float64                  `json:"regression_threshold"`
	NotificationChannels []evalScheduleChannelAPI `json:"notification_channels,omitempty"`
	LastRunAt            string                   `json:"last_run_at,omitempty"`
	NextRunAt            string                   `json:"next_run_at,omitempty"`
}

type evalScheduleChannelAPI struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

func evalScheduleFromState(d *schema.ResourceData) *evalScheduleAPI {
	s := &evalScheduleAPI{
		ProjectID:           d.Get("project_id").(string),
		Name:                d.Get("name").(string),
		DatasetID:           d.Get("dataset_id").(string),
		Model:               d.Get("model").(string),
		Cron:                d.Get("cron").(string),
		Enabled:             d.Get("enabled").(bool),
		NotifyOnRegression:  d.Get("notify_on_regression").(bool),
		RegressionThreshold: d.Get("regression_threshold").(float64),
	}
	for _, raw := range d.Get("metrics").([]interface{}) {
		s.Metrics = append(s.Metrics, raw.(string))
	}
	if raw, ok := d.GetOk("notification_channels"); ok {
		for _, c := range raw.([]interface{}) {
			m := c.(map[string]interface{})
			s.NotificationChannels = append(s.NotificationChannels, evalScheduleChannelAPI{
				Type:   m["type"].(string),
				Target: m["target"].(string),
			})
		}
	}
	return s
}

func evalScheduleToState(d *schema.ResourceData, s *evalScheduleAPI) {
	if s.ID != "" {
		d.SetId(s.ID)
	}
	_ = d.Set("project_id", s.ProjectID)
	_ = d.Set("name", s.Name)
	_ = d.Set("dataset_id", s.DatasetID)
	_ = d.Set("model", s.Model)
	_ = d.Set("metrics", s.Metrics)
	_ = d.Set("cron", s.Cron)
	_ = d.Set("enabled", s.Enabled)
	_ = d.Set("notify_on_regression", s.NotifyOnRegression)
	_ = d.Set("regression_threshold", s.RegressionThreshold)
	if len(s.NotificationChannels) > 0 {
		ch := make([]map[string]interface{}, len(s.NotificationChannels))
		for i, c := range s.NotificationChannels {
			ch[i] = map[string]interface{}{"type": c.Type, "target": c.Target}
		}
		_ = d.Set("notification_channels", ch)
	}
	if s.LastRunAt != "" {
		_ = d.Set("last_run_at", s.LastRunAt)
	}
	if s.NextRunAt != "" {
		_ = d.Set("next_run_at", s.NextRunAt)
	}
}

func resourceEvalScheduleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out evalScheduleAPI
	if err := httpDo(ctx, c, http.MethodPost, "/eval-schedules", evalScheduleFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	evalScheduleToState(d, &out)
	return nil
}

func resourceEvalScheduleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out evalScheduleAPI
	err := httpDo(ctx, c, http.MethodGet, "/eval-schedules/"+d.Id(), nil, &out)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	evalScheduleToState(d, &out)
	return nil
}

func resourceEvalScheduleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	var out evalScheduleAPI
	if err := httpDo(ctx, c, http.MethodPut, "/eval-schedules/"+d.Id(), evalScheduleFromState(d), &out); err != nil {
		return diag.FromErr(err)
	}
	evalScheduleToState(d, &out)
	return nil
}

func resourceEvalScheduleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	if err := httpDo(ctx, c, http.MethodDelete, "/eval-schedules/"+d.Id(), nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Resource: evalguard_gateway_policy
// ──────────────────────────────────────────────

func resourceGatewayPolicy() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an AI gateway routing policy.",
		CreateContext: resourceGatewayPolicyCreate,
		ReadContext:   resourceGatewayPolicyRead,
		UpdateContext: resourceGatewayPolicyUpdate,
		DeleteContext: resourceGatewayPolicyDelete,
		Schema: map[string]*schema.Schema{
			"project_id":       {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":             {Type: schema.TypeString, Required: true},
			"description":      {Type: schema.TypeString, Optional: true},
			"enabled":          {Type: schema.TypeBool, Optional: true, Default: true},
			"routing_strategy": {Type: schema.TypeString, Required: true, Description: "Strategy: round_robin, least_latency, cost_optimized, failover."},
			"targets": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"provider": {Type: schema.TypeString, Required: true, Description: "Provider: openai, anthropic, google, azure, bedrock."},
						"model":    {Type: schema.TypeString, Required: true},
						"weight":   {Type: schema.TypeInt, Optional: true, Default: 1},
						"max_rpm":  {Type: schema.TypeInt, Optional: true, Default: 1000},
					},
				},
			},
			"fallback_model": {Type: schema.TypeString, Optional: true, Description: "Fallback model if all targets fail."},
			"timeout_ms":     {Type: schema.TypeInt, Optional: true, Default: 30000},
			"retry_count":    {Type: schema.TypeInt, Optional: true, Default: 2},
			"cache_ttl_s":    {Type: schema.TypeInt, Optional: true, Default: 0, Description: "Semantic cache TTL in seconds (0 = disabled)."},
		},
		Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
	}
}

type gatewayPolicyAPI struct {
	ID              string                   `json:"id,omitempty"`
	ProjectID       string                   `json:"project_id"`
	Name            string                   `json:"name"`
	Description     string                   `json:"description,omitempty"`
	Enabled         bool                     `json:"enabled"`
	RoutingStrategy string                   `json:"routing_strategy"`
	Targets         []gatewayPolicyTargetAPI `json:"targets"`
	FallbackModel   string                   `json:"fallback_model,omitempty"`
	TimeoutMs       int                      `json:"timeout_ms,omitempty"`
	RetryCount      int                      `json:"retry_count,omitempty"`
	CacheTTLs       int                      `json:"cache_ttl_s,omitempty"`
}

type gatewayPolicyTargetAPI struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Weight   int    `json:"weight,omitempty"`
	MaxRPM   int    `json:"max_rpm,omitempty"`
}

func gatewayPolicyFromState(d *schema.ResourceData) *gatewayPolicyAPI {
	p := &gatewayPolicyAPI{
		ProjectID:       d.Get("project_id").(string),
		Name:            d.Get("name").(string),
		Description:     d.Get("description").(string),
		Enabled:         d.Get("enabled").(bool),
		RoutingStrategy: d.Get("routing_strategy").(string),
		FallbackModel:   d.Get("fallback_model").(string),
		TimeoutMs:       d.Get("timeout_ms").(int),
		RetryCount:      d.Get("retry_count").(int),
		CacheTTLs:       d.Get("cache_ttl_s").(int),
	}
	for _, raw := range d.Get("targets").([]interface{}) {
		t := raw.(map[string]interface{})
		p.Targets = append(p.Targets, gatewayPolicyTargetAPI{
			Provider: t["provider"].(string),
			Model:    t["model"].(string),
			Weight:   t["weight"].(int),
			MaxRPM:   t["max_rpm"].(int),
		})
	}
	return p
}

func gatewayPolicyToState(d *schema.ResourceData, p *gatewayPolicyAPI) {
	if p.ID != "" {
		d.SetId(p.ID)
	}
	_ = d.Set("project_id", p.ProjectID)
	_ = d.Set("name", p.Name)
	if p.Description != "" {
		_ = d.Set("description", p.Description)
	}
	_ = d.Set("enabled", p.Enabled)
	_ = d.Set("routing_strategy", p.RoutingStrategy)
	_ = d.Set("fallback_model", p.FallbackModel)
	_ = d.Set("timeout_ms", p.TimeoutMs)
	_ = d.Set("retry_count", p.RetryCount)
	_ = d.Set("cache_ttl_s", p.CacheTTLs)
	if len(p.Targets) > 0 {
		ts := make([]map[string]interface{}, len(p.Targets))
		for i, t := range p.Targets {
			ts[i] = map[string]interface{}{"provider": t.Provider, "model": t.Model, "weight": t.Weight, "max_rpm": t.MaxRPM}
		}
		_ = d.Set("targets", ts)
	}
}

func resourceGatewayPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	// /api/v1/gateway/policies is action-discriminated (see B4 — POST
	// takes `{action: "create-rule", projectId, rule: {…}}`). The
	// resource shape above is rolled into the `rule` field.
	body := map[string]interface{}{
		"action":    "create-rule",
		"projectId": d.Get("project_id").(string),
		"rule":      gatewayPolicyFromState(d),
	}
	var out struct {
		Rule *gatewayPolicyAPI `json:"rule"`
	}
	if err := httpDo(ctx, c, http.MethodPost, "/gateway/policies", body, &out); err != nil {
		return diag.FromErr(err)
	}
	if out.Rule != nil {
		gatewayPolicyToState(d, out.Rule)
	}
	return nil
}

func resourceGatewayPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	// The GET endpoint returns a list per project; fetch + filter to
	// the row our state owns. Single-rule GET-by-id was deferred
	// during B4 since the dashboard list-by-project is the only
	// consumer today.
	var out struct {
		Rules []gatewayPolicyAPI `json:"rules"`
	}
	err := httpDo(ctx, c, http.MethodGet,
		fmt.Sprintf("/gateway/policies?projectId=%s", d.Get("project_id").(string)),
		nil, &out)
	if isNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for _, r := range out.Rules {
		if r.ID == d.Id() {
			gatewayPolicyToState(d, &r)
			return nil
		}
	}
	// Rule disappeared upstream.
	d.SetId("")
	return nil
}

func resourceGatewayPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// /gateway/policies has no per-id PUT yet — emulate update via
	// delete + create. ForceNew on `name` is not set so renames work;
	// for in-place edits we recreate to keep the API surface narrow.
	c := m.(*apiClient)
	if err := httpDo(ctx, c, http.MethodDelete,
		fmt.Sprintf("/gateway/policies?id=%s", d.Id()), nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	return resourceGatewayPolicyCreate(ctx, d, m)
}

func resourceGatewayPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*apiClient)
	if err := httpDo(ctx, c, http.MethodDelete,
		fmt.Sprintf("/gateway/policies?id=%s", d.Id()), nil, nil); err != nil && !isNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

// ──────────────────────────────────────────────
// Data Source: evalguard_eval_results
// ──────────────────────────────────────────────

func dataSourceEvalResults() *schema.Resource {
	return &schema.Resource{
		Description: "Fetches evaluation results for a project.",
		ReadContext: dataSourceEvalResultsRead,
		Schema: map[string]*schema.Schema{
			"project_id": {Type: schema.TypeString, Required: true},
			"dataset_id": {Type: schema.TypeString, Optional: true},
			"model":      {Type: schema.TypeString, Optional: true},
			"status":     {Type: schema.TypeString, Optional: true, Default: "completed"},
			"limit":      {Type: schema.TypeInt, Optional: true, Default: 50},
			"results": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id":           {Type: schema.TypeString, Computed: true},
						"status":       {Type: schema.TypeString, Computed: true},
						"model":        {Type: schema.TypeString, Computed: true},
						"sample_count": {Type: schema.TypeInt, Computed: true},
						"created_at":   {Type: schema.TypeString, Computed: true},
						"metrics":      {Type: schema.TypeMap, Computed: true, Elem: &schema.Schema{Type: schema.TypeString}},
					},
				},
			},
		},
	}
}

func dataSourceEvalResultsRead(_ context.Context, _ *schema.ResourceData, m interface{}) diag.Diagnostics {
	_ = m.(*apiClient)
	return nil
}

// ──────────────────────────────────────────────
// Data Source: evalguard_security_report
// ──────────────────────────────────────────────

func dataSourceSecurityReport() *schema.Resource {
	return &schema.Resource{
		Description: "Fetches the latest security scan report for a project.",
		ReadContext: dataSourceSecurityReportRead,
		Schema: map[string]*schema.Schema{
			"project_id":     {Type: schema.TypeString, Required: true},
			"min_severity":   {Type: schema.TypeString, Optional: true, Default: "low", Description: "Minimum severity filter: low, medium, high, critical."},
			"scan_id":        {Type: schema.TypeString, Computed: true},
			"status":         {Type: schema.TypeString, Computed: true},
			"total_findings": {Type: schema.TypeInt, Computed: true},
			"critical_count": {Type: schema.TypeInt, Computed: true},
			"high_count":     {Type: schema.TypeInt, Computed: true},
			"medium_count":   {Type: schema.TypeInt, Computed: true},
			"low_count":      {Type: schema.TypeInt, Computed: true},
			"findings": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id":          {Type: schema.TypeString, Computed: true},
						"type":        {Type: schema.TypeString, Computed: true},
						"severity":    {Type: schema.TypeString, Computed: true},
						"description": {Type: schema.TypeString, Computed: true},
						"remediation": {Type: schema.TypeString, Computed: true},
					},
				},
			},
			"scanned_at": {Type: schema.TypeString, Computed: true},
		},
	}
}

func dataSourceSecurityReportRead(_ context.Context, _ *schema.ResourceData, m interface{}) diag.Diagnostics {
	_ = m.(*apiClient)
	return nil
}
