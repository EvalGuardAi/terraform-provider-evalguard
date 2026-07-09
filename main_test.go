// Integration tests for the EvalGuard Terraform provider.
//
// Each test starts an in-process httptest server that impersonates
// the /api/v1 surface, points the provider's apiClient at it, and
// drives the resource Create/Read/Update/Delete handlers directly
// through the schema.ResourceData interface. This is the same pattern
// the official HashiCorp providers use (cf. terraform-provider-aws's
// acctest harness, scaled down — we don't need the full TestStep
// runner for round-trip coverage).
//
// What we verify per resource:
//   1. Create POSTs the right path with the right body and stores
//      the server-returned id in state.
//   2. Read GETs the right path and populates state fields from
//      the response.
//   3. Update PATCHes the right path with the changed fields only.
//   4. Delete DELETEs the right path and clears state on success.
//   5. Read against a 404 clears state without error (drift-detection).
//   6. Every mutating request carries Authorization: Bearer + the
//      x-requested-with header (required by `createApiHandler`'s
//      CSRF gate).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ─── Mock server ──────────────────────────────────────────────────────────

type mockRoute struct {
	method   string
	path     string
	status   int
	body     string
	captured *http.Request
	gotBody  []byte
}

type mockServer struct {
	t          *testing.T
	routes     []*mockRoute
	hits       map[string]int
	authHeader string
	csrfHeader string
}

func newMockServer(t *testing.T, routes ...*mockRoute) *mockServer {
	return &mockServer{t: t, routes: routes, hits: map[string]int{}}
}

func (m *mockServer) serve() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.authHeader = r.Header.Get("Authorization")
		m.csrfHeader = r.Header.Get("x-requested-with")

		for _, route := range m.routes {
			if route.method != r.Method {
				continue
			}
			if !pathMatches(route.path, r.URL.Path) {
				continue
			}
			m.hits[route.method+" "+route.path]++
			route.captured = r
			if r.Body != nil {
				route.gotBody, _ = io.ReadAll(r.Body)
			}
			w.WriteHeader(route.status)
			if route.body != "" {
				_, _ = io.WriteString(w, route.body)
			}
			return
		}
		// Unmatched route — fail loud so tests see the typo.
		m.t.Errorf("mock: no route for %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
}

func pathMatches(pattern, actual string) bool {
	// Pattern uses ":id" wildcards (e.g. /projects/:id matches /projects/abc).
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	ap := strings.Split(strings.Trim(actual, "/"), "/")
	if len(pp) != len(ap) {
		return false
	}
	for i := range pp {
		if strings.HasPrefix(pp[i], ":") {
			continue
		}
		if pp[i] != ap[i] {
			return false
		}
	}
	return true
}

func envelope(data string) string {
	return `{"success":true,"data":` + data + `}`
}

// ─── httpDo + auth header tests ───────────────────────────────────────────

func TestHttpDo_AuthHeaderAndCSRFShim(t *testing.T) {
	srv := newMockServer(t, &mockRoute{
		method: "POST", path: "/projects", status: 201,
		body: envelope(`{"id":"p_1","name":"x"}`),
	})
	ts := srv.serve()
	defer ts.Close()

	c := &apiClient{
		apiKey:  "eg_test_secret",
		baseURL: ts.URL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
	var out map[string]any
	if err := httpDo(context.Background(), c, http.MethodPost, "/projects", map[string]string{"name": "x"}, &out); err != nil {
		t.Fatal(err)
	}
	if got := srv.authHeader; got != "Bearer eg_test_secret" {
		t.Errorf("Authorization header: want 'Bearer eg_test_secret', got %q", got)
	}
	if got := srv.csrfHeader; got != "terraform-provider" {
		t.Errorf("x-requested-with header: want 'terraform-provider', got %q", got)
	}
	if out["id"] != "p_1" {
		t.Errorf("body decoded wrong: %+v", out)
	}
}

func TestHttpDo_UnwrapsEnvelope(t *testing.T) {
	srv := newMockServer(t, &mockRoute{
		method: "GET", path: "/x", status: 200,
		body: envelope(`{"nested":{"a":42}}`),
	})
	ts := srv.serve()
	defer ts.Close()

	c := &apiClient{
		apiKey:  "k",
		baseURL: ts.URL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
	var out map[string]any
	if err := httpDo(context.Background(), c, http.MethodGet, "/x", nil, &out); err != nil {
		t.Fatal(err)
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok || nested["a"].(float64) != 42 {
		t.Errorf("envelope unwrap broken: %+v", out)
	}
}

func TestHttpDo_404YieldsApiNotFoundError(t *testing.T) {
	srv := newMockServer(t, &mockRoute{
		method: "GET", path: "/projects/:id", status: 404, body: "",
	})
	ts := srv.serve()
	defer ts.Close()

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	err := httpDo(context.Background(), c, http.MethodGet, "/projects/gone", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !isNotFound(err) {
		t.Errorf("expected apiNotFoundError, got %T: %v", err, err)
	}
}

func TestHttpDo_5xxYieldsError(t *testing.T) {
	srv := newMockServer(t, &mockRoute{
		method: "POST", path: "/x", status: 500,
		body: `{"success":false,"error":{"code":"INTERNAL","message":"oops"}}`,
	})
	ts := srv.serve()
	defer ts.Close()

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	err := httpDo(context.Background(), c, http.MethodPost, "/x", map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code: %v", err)
	}
}

// ─── Provider schema sanity ───────────────────────────────────────────────

func TestProvider_RegistersFiveResources(t *testing.T) {
	p := Provider()
	resources := p.ResourcesMap
	expected := []string{
		"evalguard_project",
		"evalguard_api_key",
		"evalguard_firewall_rule",
		"evalguard_eval_schedule",
		"evalguard_gateway_policy",
	}
	if len(resources) != len(expected) {
		t.Fatalf("expected %d resources, got %d: %v", len(expected), len(resources), keys(resources))
	}
	for _, name := range expected {
		if _, ok := resources[name]; !ok {
			t.Errorf("missing resource %q", name)
		}
	}
}

func TestProvider_NoStubResourcesPresent(t *testing.T) {
	// Defensive: ensure the previously-shipped stub resources never sneak back
	// without their httpDo wiring. Each name corresponds to a former
	// genericCRUD() resource that's been removed pending real implementation.
	p := Provider()
	removed := []string{
		"evalguard_scorer", "evalguard_dataset", "evalguard_member",
		"evalguard_team", "evalguard_provider_key", "evalguard_audit_destination",
		"evalguard_alert", "evalguard_compliance_framework_subscription",
		"evalguard_eval_run", "evalguard_role", "evalguard_vault_config",
		"evalguard_mcp_server", "evalguard_mcp_tool_permission",
		"evalguard_persona", "evalguard_red_team_config",
	}
	for _, name := range removed {
		if _, ok := p.ResourcesMap[name]; ok {
			t.Errorf("stub resource %q resurrected — must be wired to real /api/v1 before re-registering", name)
		}
	}
}

func TestProvider_SchemaValidates(t *testing.T) {
	// InternalValidate exercises terraform-plugin-sdk's schema checker
	// — it would catch missing required-but-no-default keys, type mismatches,
	// invalid Computed+Required combinations, etc. Fails the build before
	// `terraform init` would ever see the broken schema.
	p := Provider()
	if err := p.InternalValidate(); err != nil {
		t.Fatalf("provider schema validation failed: %v", err)
	}
}

// ─── Resource CRUD round-trips ────────────────────────────────────────────
//
// These drive the real Create/Read/Update/Delete functions against a mock that
// speaks the API's ACTUAL contract (verified against apps/web/src/app/api/v1/*
// on 2026-07-09). The v1.0.0 suite passed while the provider was unusable
// because its mock spoke an invented contract; TestContract_* below pins the
// request bodies so that can't recur silently.

func TestResourceProject_CreateThenRead(t *testing.T) {
	const row = `{"id":"p_42","org_id":"org_1","name":"acme","slug":"acme","settings":{},"created_at":"2026-05-21T00:00:00Z","updated_at":"2026-05-21T00:00:00Z"}`
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/projects", status: 201, body: envelope(row)},
		&mockRoute{method: "GET", path: "/projects/:id", status: 200, body: envelope(row)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	_ = d.Set("org_id", "org_1")
	_ = d.Set("name", "acme")
	_ = d.Set("slug", "acme")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceProjectCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "p_42" {
		t.Fatalf("id not stored: %q", d.Id())
	}
	if got := d.Get("slug").(string); got != "acme" {
		t.Errorf("slug not read back: %q", got)
	}
	if got := d.Get("org_id").(string); got != "org_1" {
		t.Errorf("org_id not read back: %q", got)
	}
}

func TestResourceProject_ReadMissingClearsState(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "GET", path: "/projects/:id", status: 404, body: ""},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	d.SetId("p_gone")
	_ = d.Set("org_id", "org_1")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceProjectRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read of a deleted project must not error: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("state not cleared for a 404: id=%q", d.Id())
	}
}

func TestResourceProject_UpdatePatchesPerIdPath(t *testing.T) {
	const row = `{"id":"p_42","org_id":"org_1","name":"renamed","slug":"acme"}`
	patch := &mockRoute{method: "PATCH", path: "/projects/:id", status: 200, body: envelope(row)}
	srv := newMockServer(t,
		patch,
		&mockRoute{method: "GET", path: "/projects/:id", status: 200, body: envelope(row)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	d.SetId("p_42")
	_ = d.Set("org_id", "org_1")
	_ = d.Set("name", "renamed")
	_ = d.Set("slug", "acme")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceProjectUpdate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("update failed: %v", diags)
	}
	if patch.gotBody == nil {
		t.Fatal("PATCH /projects/{id} was never called")
	}
}

func TestResourceProject_DeleteHitsPerIdPath(t *testing.T) {
	del := &mockRoute{method: "DELETE", path: "/projects/:id", status: 200,
		body: envelope(`{"id":"p_42","deleted":true}`)}
	srv := newMockServer(t, del)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	d.SetId("p_42")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceProjectDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if del.captured == nil || del.captured.URL.Path != "/projects/p_42" {
		t.Errorf("delete hit the wrong path: %+v", del.captured)
	}
	if d.Id() != "" {
		t.Errorf("state not cleared after delete")
	}
}

func TestResourceAPIKey_CreateStoresSecretThenDelete(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/api-keys", status: 201,
		body: envelope(`{"id":"k_1","name":"ci","key_prefix":"eg_abc","created_at":"2026-07-09T00:00:00Z","rawKey":"eg_secret_value"}`)}
	srv := newMockServer(t,
		create,
		&mockRoute{method: "GET", path: "/api-keys", status: 200,
			body: envelope(`[{"id":"k_1","org_id":"org_1","name":"ci","key_prefix":"eg_abc","scopes":["firewall:check"],"revoked":false}]`)},
		&mockRoute{method: "DELETE", path: "/api-keys/:id", status: 200, body: envelope(`{"id":"k_1","revoked":true}`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceAPIKey()
	d := r.TestResourceData()
	_ = d.Set("org_id", "org_1")
	_ = d.Set("name", "ci")
	_ = d.Set("scopes", []interface{}{"firewall:check"})

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceAPIKeyCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "k_1" {
		t.Fatalf("id not stored: %q", d.Id())
	}
	// The raw secret is returned exactly once — losing it here would make the
	// resource useless for wiring a key into another provider.
	if got := d.Get("key").(string); got != "eg_secret_value" {
		t.Errorf("raw key not persisted to state: %q", got)
	}

	if diags := resourceAPIKeyDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
}

func TestResourceAPIKey_RevokedKeyClearsState(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "GET", path: "/api-keys", status: 200,
			body: envelope(`[{"id":"k_1","org_id":"org_1","name":"ci","revoked":true}]`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceAPIKey()
	d := r.TestResourceData()
	d.SetId("k_1")
	_ = d.Set("org_id", "org_1")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceAPIKeyRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if d.Id() != "" {
		t.Error("a server-side revoked key must drop out of state, not look healthy")
	}
}

func TestResourceAPIKey_ReadAcceptsPaginatedShape(t *testing.T) {
	// GET /api-keys returns either a bare array or {keys,total}. Both must work.
	srv := newMockServer(t,
		&mockRoute{method: "GET", path: "/api-keys", status: 200,
			body: envelope(`{"keys":[{"id":"k_1","org_id":"org_1","name":"ci","revoked":false}],"total":1}`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceAPIKey()
	d := r.TestResourceData()
	d.SetId("k_1")
	_ = d.Set("org_id", "org_1")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceAPIKeyRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if d.Id() != "k_1" || d.Get("name").(string) != "ci" {
		t.Errorf("paginated list shape not handled: id=%q name=%q", d.Id(), d.Get("name"))
	}
}

func TestResourceFirewallRule_CreateAndReadRoundTrip(t *testing.T) {
	const rule = `{"id":"r_1","project_id":"proj_1","name":"block-injection","type":"regex","condition":{"pattern":"ignore previous"},"action":{"type":"block"},"priority":10,"enabled":true}`
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/firewall/rules", status: 201, body: envelope(rule)},
		&mockRoute{method: "GET", path: "/firewall/rules", status: 200, body: envelope(`[` + rule + `]`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceFirewallRule()
	d := r.TestResourceData()
	_ = d.Set("project_id", "proj_1")
	_ = d.Set("name", "block-injection")
	_ = d.Set("type", "regex")
	_ = d.Set("condition", `{"pattern":"ignore previous"}`)
	_ = d.Set("action", `{"type":"block"}`)

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceFirewallRuleCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "r_1" {
		t.Fatalf("id not stored: %q", d.Id())
	}
	if got := d.Get("type").(string); got != "regex" {
		t.Errorf("type not read back: %q", got)
	}
	// The JSON fields must survive a server round-trip without a perpetual diff.
	if got := d.Get("condition").(string); got != `{"pattern":"ignore previous"}` {
		t.Errorf("condition not canonicalized: %q", got)
	}
}

func TestResourceFirewallRule_DeletePassesRuleIdAndProjectId(t *testing.T) {
	del := &mockRoute{method: "DELETE", path: "/firewall/rules", status: 200, body: envelope(`{}`)}
	srv := newMockServer(t, del)
	ts := srv.serve()
	defer ts.Close()

	r := resourceFirewallRule()
	d := r.TestResourceData()
	d.SetId("r_1")
	_ = d.Set("project_id", "proj_1")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceFirewallRuleDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	q := del.captured.URL.Query()
	if q.Get("ruleId") != "r_1" || q.Get("projectId") != "proj_1" {
		t.Errorf("delete must send ruleId + projectId, got %v", q)
	}
}

func TestResourceEvalSchedule_CreateThenRead(t *testing.T) {
	const row = `{"id":"s_1","project_id":"proj_1","name":"nightly","cron_expression":"0 3 * * *","config":{"model":"gpt-4"},"enabled":true}`
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/eval-schedules", status: 201, body: envelope(row)},
		&mockRoute{method: "GET", path: "/eval-schedules", status: 200, body: envelope(`[` + row + `]`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceEvalSchedule()
	d := r.TestResourceData()
	_ = d.Set("project_id", "proj_1")
	_ = d.Set("name", "nightly")
	_ = d.Set("cron_expression", "0 3 * * *")
	_ = d.Set("config", `{"model":"gpt-4"}`)

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceEvalScheduleCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "s_1" {
		t.Fatalf("id not stored: %q", d.Id())
	}
	if got := d.Get("cron_expression").(string); got != "0 3 * * *" {
		t.Errorf("cron_expression not read back: %q", got)
	}
}

func TestResourceGatewayPolicy_CreateAndDelete(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/gateway/policies", status: 201,
		body: envelope(`{"rule":{"id":"gp_1","project_id":"proj_1","name":"deny-http","effect":"deny","priority":100,"conditions":{}}}`)}
	del := &mockRoute{method: "DELETE", path: "/gateway/policies", status: 200, body: envelope(`{}`)}
	srv := newMockServer(t,
		create,
		&mockRoute{method: "GET", path: "/gateway/policies", status: 200,
			body: envelope(`{"rules":[{"id":"gp_1","project_id":"proj_1","name":"deny-http","effect":"deny","priority":100}],"appliedTemplates":[]}`)},
		del,
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceGatewayPolicy()
	d := r.TestResourceData()
	_ = d.Set("project_id", "proj_1")
	_ = d.Set("name", "deny-http")
	_ = d.Set("effect", "deny")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceGatewayPolicyCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "gp_1" {
		t.Fatalf("id not unwrapped from {rule:{...}}: %q", d.Id())
	}
	if diags := resourceGatewayPolicyDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if del.captured.URL.Query().Get("id") != "gp_1" {
		t.Errorf("delete must send ?id=, got %v", del.captured.URL.RawQuery)
	}
}

// ─── Contract tests ───────────────────────────────────────────────────────
//
// These assert the exact JSON the provider PUTS ON THE WIRE against the field
// names the server's zod schemas require. They are the guard against the
// v1.0.0 failure mode: a mock that agrees with the client and disagrees with
// the server. If someone renames a field back to snake_case, or drops `slug`,
// these fail — the round-trip tests above would not.

func bodyOf(t *testing.T, route *mockRoute) map[string]interface{} {
	t.Helper()
	if route.gotBody == nil {
		t.Fatal("route captured no body")
	}
	var got map[string]interface{}
	if err := json.Unmarshal(route.gotBody, &got); err != nil {
		t.Fatalf("request body was not a JSON object: %v", err)
	}
	return got
}

func requireKeys(t *testing.T, got map[string]interface{}, want ...string) {
	t.Helper()
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("request body is missing required field %q (server rejects with 400 VALIDATION_ERROR); body=%v", k, got)
		}
	}
}

func forbidKeys(t *testing.T, got map[string]interface{}, forbidden ...string) {
	t.Helper()
	for _, k := range forbidden {
		if _, ok := got[k]; ok {
			t.Errorf("request body carries %q, which the server does not accept; body=%v", k, got)
		}
	}
}

// POST /api/v1/projects → createProjectSchema {name, slug} + orgId.
func TestContract_ProjectCreateBody(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/projects", status: 201,
		body: envelope(`{"id":"p_1","org_id":"org_1","name":"acme","slug":"acme"}`)}
	srv := newMockServer(t, create,
		&mockRoute{method: "GET", path: "/projects/:id", status: 200,
			body: envelope(`{"id":"p_1","org_id":"org_1","name":"acme","slug":"acme"}`)})
	ts := srv.serve()
	defer ts.Close()

	d := resourceProject().TestResourceData()
	_ = d.Set("org_id", "org_1")
	_ = d.Set("name", "acme")
	_ = d.Set("slug", "acme")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceProjectCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	got := bodyOf(t, create)
	requireKeys(t, got, "name", "slug", "orgId")
	forbidKeys(t, got, "org_id", "environment", "tags", "description")
}

// POST /api/v1/firewall/rules → {projectId, rule:{name,type,condition,action}}.
func TestContract_FirewallRuleCreateBody(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/firewall/rules", status: 201,
		body: envelope(`{"id":"r_1","project_id":"proj_1","name":"n","type":"regex","condition":{},"action":{},"enabled":true}`)}
	srv := newMockServer(t, create,
		&mockRoute{method: "GET", path: "/firewall/rules", status: 200, body: envelope(`[]`)})
	ts := srv.serve()
	defer ts.Close()

	d := resourceFirewallRule().TestResourceData()
	_ = d.Set("project_id", "proj_1")
	_ = d.Set("name", "n")
	_ = d.Set("type", "regex")
	_ = d.Set("condition", `{"pattern":"x"}`)
	_ = d.Set("action", `{"type":"block"}`)

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceFirewallRuleCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	got := bodyOf(t, create)
	requireKeys(t, got, "projectId", "rule")
	forbidKeys(t, got, "project_id", "rule_type", "conditions")

	rule, ok := got["rule"].(map[string]interface{})
	if !ok {
		t.Fatalf("rule must be a nested object, got %T", got["rule"])
	}
	requireKeys(t, rule, "name", "type", "condition", "action")
	forbidKeys(t, rule, "rule_type", "conditions")
}

// POST /api/v1/eval-schedules → {projectId, name, cronExpression, config}.
func TestContract_EvalScheduleCreateBody(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/eval-schedules", status: 201,
		body: envelope(`{"id":"s_1","project_id":"proj_1","name":"n"}`)}
	srv := newMockServer(t, create,
		&mockRoute{method: "GET", path: "/eval-schedules", status: 200, body: envelope(`[]`)})
	ts := srv.serve()
	defer ts.Close()

	d := resourceEvalSchedule().TestResourceData()
	_ = d.Set("project_id", "proj_1")
	_ = d.Set("name", "n")
	_ = d.Set("cron_expression", "0 3 * * *")
	_ = d.Set("config", `{"model":"gpt-4"}`)

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceEvalScheduleCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	got := bodyOf(t, create)
	requireKeys(t, got, "projectId", "name", "cronExpression", "config")
	forbidKeys(t, got, "project_id", "cron", "dataset_id", "model", "metrics")
}

// POST /api/v1/api-keys → {orgId, name, scopes, expiresAt?}.
func TestContract_APIKeyCreateBody(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/api-keys", status: 201,
		body: envelope(`{"id":"k_1","name":"ci","rawKey":"eg_x"}`)}
	srv := newMockServer(t, create,
		&mockRoute{method: "GET", path: "/api-keys", status: 200, body: envelope(`[]`)})
	ts := srv.serve()
	defer ts.Close()

	d := resourceAPIKey().TestResourceData()
	_ = d.Set("org_id", "org_1")
	_ = d.Set("name", "ci")
	_ = d.Set("scopes", []interface{}{"firewall:check"})

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceAPIKeyCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	got := bodyOf(t, create)
	requireKeys(t, got, "orgId", "name")
	forbidKeys(t, got, "org_id", "project_id", "expires_at")
}

// POST /api/v1/gateway/policies → discriminated union on `action`.
func TestContract_GatewayPolicyCreateBody(t *testing.T) {
	create := &mockRoute{method: "POST", path: "/gateway/policies", status: 201,
		body: envelope(`{"rule":{"id":"gp_1","name":"n","effect":"deny"}}`)}
	srv := newMockServer(t, create,
		&mockRoute{method: "GET", path: "/gateway/policies", status: 200,
			body: envelope(`{"rules":[],"appliedTemplates":[]}`)})
	ts := srv.serve()
	defer ts.Close()

	d := resourceGatewayPolicy().TestResourceData()
	_ = d.Set("project_id", "proj_1")
	_ = d.Set("name", "n")
	_ = d.Set("effect", "deny")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceGatewayPolicyCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	got := bodyOf(t, create)
	requireKeys(t, got, "action", "projectId", "rule")
	if got["action"] != "create-rule" {
		t.Errorf("action must be the literal \"create-rule\", got %v", got["action"])
	}
	forbidKeys(t, got, "project_id", "routing_strategy", "targets", "fallback_model")

	rule, ok := got["rule"].(map[string]interface{})
	if !ok {
		t.Fatalf("rule must be a nested object, got %T", got["rule"])
	}
	requireKeys(t, rule, "name", "effect", "priority")
}

// The provider must never point at the /v1 prefix again: that path is served by
// the Next.js page router and returns an HTML login redirect, not the API.
func TestProvider_DefaultBaseURLTargetsTheAPI(t *testing.T) {
	def, err := Provider().Schema["base_url"].DefaultValue()
	if err != nil {
		t.Fatalf("base_url default: %v", err)
	}
	got, _ := def.(string)
	if got != "https://evalguard.ai/api/v1" {
		t.Errorf("default base_url must be the real API root, got %q", got)
	}
	if strings.HasSuffix(got, "/v1") && !strings.HasSuffix(got, "/api/v1") {
		t.Errorf("base_url %q hits the page router, not /api/v1", got)
	}
}

func TestProvider_NoNoOpDataSources(t *testing.T) {
	// v1.0.0 advertised two data sources whose Read functions returned nil
	// without ever calling the API. A data source with no HTTP call is a lie
	// told in schema form.
	if n := len(Provider().DataSourcesMap); n != 0 {
		t.Errorf("expected 0 data sources until one is backed by a real read, got %d", n)
	}
}

func TestJSONObjectHelpers_RoundTrip(t *testing.T) {
	in := `{"a":1,"b":"two"}`
	obj, err := decodeJSONObject(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out, err := encodeJSONObject(obj)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Canonical (key-sorted) form must be stable, else every plan shows a diff.
	again, err := decodeJSONObject(out)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if len(again) != 2 || again["b"] != "two" {
		t.Errorf("round-trip lost data: %v", again)
	}
	if empty, _ := encodeJSONObject(map[string]interface{}{}); empty != "" {
		t.Errorf("an empty object must encode to the empty string, got %q", empty)
	}
}

func TestJSONObjectString_RejectsNonObject(t *testing.T) {
	if d := jsonObjectString("[1,2]", cty.Path{}); !d.HasError() {
		t.Error("a JSON array must be rejected")
	}
	if d := jsonObjectString("not json", cty.Path{}); !d.HasError() {
		t.Error("invalid JSON must be rejected")
	}
	if d := jsonObjectString("", cty.Path{}); d.HasError() {
		t.Error("an empty string is allowed (field omitted)")
	}
	if d := jsonObjectString(`{"a":1}`, cty.Path{}); d.HasError() {
		t.Error("a valid JSON object must be accepted")
	}
}

// ─── helpers ───────────────────────────────────────────────────────────────

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Silences unused-warning when narrowed builds drop some helpers.
var _ = fmt.Sprintf

// ─── Security + resilience hardening tests (2026-07-08) ───────────────────

func TestValidateHTTPSURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{"https ok", "https://api.evalguard.ai/v1", true},
		{"https custom host", "https://eg.internal.acme.com/api/v1", true},
		{"http localhost ok (dev)", "http://localhost:3001/api/v1", true},
		{"http 127.0.0.1 ok (dev)", "http://127.0.0.1:8080", true},
		{"http remote rejected", "http://api.evalguard.ai/v1", false},
		{"ftp rejected", "ftp://api.evalguard.ai", false},
		{"relative rejected", "/api/v1", false},
		{"empty rejected", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := validateHTTPSURL(tc.url, cty.Path{})
			if tc.ok && diags.HasError() {
				t.Errorf("expected %q valid, got: %v", tc.url, diags)
			}
			if !tc.ok && !diags.HasError() {
				t.Errorf("expected %q rejected", tc.url)
			}
		})
	}
}

func TestProviderConfigure_RejectsPlaintextBaseURL(t *testing.T) {
	p := Provider()
	raw := map[string]interface{}{"api_key": "k", "base_url": "http://api.evalguard.ai/v1"}
	_, diags := p.ConfigureContextFunc(context.Background(), schema.TestResourceDataRaw(t, p.Schema, raw))
	if !diags.HasError() {
		t.Fatal("configure must reject a plaintext http:// base_url (Bearer-token leak)")
	}
}

func TestProviderConfigure_RejectsEmptyAPIKey(t *testing.T) {
	p := Provider()
	raw := map[string]interface{}{"api_key": "", "base_url": "https://api.evalguard.ai/v1"}
	_, diags := p.ConfigureContextFunc(context.Background(), schema.TestResourceDataRaw(t, p.Schema, raw))
	if !diags.HasError() {
		t.Fatal("configure must reject an empty api_key")
	}
}

func TestHttpDo_RetriesOn429ThenSucceeds(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, envelope(`{"ok":true}`))
	}))
	defer ts.Close()

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{Timeout: 5 * time.Second}}
	if err := httpDo(context.Background(), c, http.MethodGet, "/x", nil, nil); err != nil {
		t.Fatalf("expected success after 429 retries, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 attempts (2×429 + 200), got %d", got)
	}
}

func TestHttpDo_DoesNotRetryPostOn5xx(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{Timeout: 5 * time.Second}}
	if err := httpDo(context.Background(), c, http.MethodPost, "/x", map[string]string{"a": "b"}, nil); err == nil {
		t.Fatal("expected error on POST 5xx")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("POST must NOT retry 5xx (double-create risk); got %d attempts", got)
	}
}

func TestHttpDo_RetriesGetOn5xx(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{Timeout: 5 * time.Second}}
	_ = httpDo(context.Background(), c, http.MethodGet, "/x", nil, nil)
	if got := atomic.LoadInt32(&calls); got != httpRetryMax+1 {
		t.Errorf("idempotent GET should retry 5xx to httpRetryMax; want %d attempts, got %d", httpRetryMax+1, got)
	}
}

// A server response that omits project_id must not blank the configured value —
// GET /firewall/rules projects rows onto FirewallRuleV2, which has no such field.
func TestResourceFirewallRule_ReadKeepsProjectIdWhenServerOmitsIt(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "GET", path: "/firewall/rules", status: 200,
			body: envelope(`[{"id":"r_1","name":"n","type":"regex","condition":{},"action":{},"enabled":true}]`)},
	)
	ts := srv.serve()
	defer ts.Close()

	d := resourceFirewallRule().TestResourceData()
	d.SetId("r_1")
	_ = d.Set("project_id", "proj_1")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: ts.Client()}
	if diags := resourceFirewallRuleRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if got := d.Get("project_id").(string); got != "proj_1" {
		t.Errorf("project_id was blanked by a response that omits it: %q", got)
	}
}
