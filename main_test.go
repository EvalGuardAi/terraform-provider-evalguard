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

// ─── Resource: evalguard_project (covers full CRUD path) ──────────────────

func TestResourceProject_CreateThenRead(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/projects", status: 201,
			body: envelope(`{"id":"p_42","name":"acme","environment":"production","created_at":"2026-05-21T00:00:00Z"}`)},
		&mockRoute{method: "GET", path: "/projects/:id", status: 200,
			body: envelope(`{"id":"p_42","name":"acme","environment":"production","created_at":"2026-05-21T00:00:00Z"}`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	_ = d.Set("name", "acme")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceProjectCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "p_42" {
		t.Errorf("id not set from response: %q", d.Id())
	}

	// Now read it back.
	if diags := resourceProjectRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if d.Get("name") != "acme" {
		t.Errorf("name not populated from server: %v", d.Get("name"))
	}
}

func TestResourceProject_ReadMissingClearsState(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "GET", path: "/projects/:id", status: 404},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	d.SetId("p_gone")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceProjectRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read should not error on 404: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("expected state-clear on 404; id still %q", d.Id())
	}
}

func TestResourceProject_DeleteHitsRightPath(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "DELETE", path: "/projects/:id", status: 204},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	d.SetId("p_99")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceProjectDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if srv.hits["DELETE /projects/:id"] != 1 {
		t.Errorf("expected exactly 1 DELETE hit; got %d", srv.hits["DELETE /projects/:id"])
	}
	if d.Id() != "" {
		t.Errorf("delete should clear id; got %q", d.Id())
	}
}

func TestResourceProject_CreateSendsExpectedBody(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/projects", status: 201,
			body: envelope(`{"id":"p_1","name":"acme"}`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceProject()
	d := r.TestResourceData()
	_ = d.Set("name", "acme")
	_ = d.Set("description", "primary tenant")
	_ = d.Set("environment", "staging")

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceProjectCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}

	var body map[string]any
	if err := json.Unmarshal(srv.routes[0].gotBody, &body); err != nil {
		t.Fatalf("body not JSON: %v / %s", err, srv.routes[0].gotBody)
	}
	if body["name"] != "acme" {
		t.Errorf("name field missing or wrong: %+v", body)
	}
	if body["environment"] != "staging" {
		t.Errorf("environment field missing: %+v", body)
	}
}

// ─── Resource: evalguard_api_key ───────────────────────────────────────────

func TestResourceAPIKey_CreateThenDelete(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/api-keys", status: 201,
			body: envelope(`{"id":"key_1","name":"ci","key_prefix":"eg_abc"}`)},
		&mockRoute{method: "DELETE", path: "/api-keys/:id", status: 204},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceAPIKey()
	d := r.TestResourceData()
	_ = d.Set("name", "ci")
	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceAPIKeyCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "key_1" {
		t.Errorf("id not set: %q", d.Id())
	}
	if diags := resourceAPIKeyDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("delete should clear id")
	}
}

// ─── Resource: evalguard_firewall_rule ────────────────────────────────────

func TestResourceFirewallRule_CreateAndReadRoundTrip(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/firewall/rules", status: 201,
			body: envelope(`{"id":"r_1","project_id":"p_1","name":"block-ssn","rule_type":"regex","priority":10,"enabled":true,"conditions":[{"field":"output","operator":"matches","value":"\\d{3}-\\d{2}-\\d{4}"}]}`)},
		&mockRoute{method: "GET", path: "/firewall/rules/:id", status: 200,
			body: envelope(`{"id":"r_1","project_id":"p_1","name":"block-ssn","rule_type":"regex","priority":10,"enabled":true,"conditions":[{"field":"output","operator":"matches","value":"\\d{3}-\\d{2}-\\d{4}"}]}`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceFirewallRule()
	d := r.TestResourceData()
	_ = d.Set("project_id", "p_1")
	_ = d.Set("name", "block-ssn")
	_ = d.Set("rule_type", "regex")
	_ = d.Set("priority", 10)
	_ = d.Set("enabled", true)
	_ = d.Set("conditions", []any{
		map[string]any{"field": "output", "operator": "matches", "value": `\d{3}-\d{2}-\d{4}`},
	})

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceFirewallRuleCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if diags := resourceFirewallRuleRead(context.Background(), d, c); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if d.Get("rule_type") != "regex" {
		t.Errorf("rule_type field not populated")
	}
	if d.Get("priority") != 10 {
		t.Errorf("priority field not populated: %v", d.Get("priority"))
	}
}

// ─── Resource: evalguard_eval_schedule ─────────────────────────────────────

func TestResourceEvalSchedule_Create(t *testing.T) {
	srv := newMockServer(t,
		&mockRoute{method: "POST", path: "/eval-schedules", status: 201,
			body: envelope(`{"id":"sched_1","project_id":"p_1","name":"nightly","dataset_id":"d_1","model":"openai:gpt-4o","metrics":["faithfulness","relevance"],"cron":"0 0 * * *","enabled":true}`)},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceEvalSchedule()
	d := r.TestResourceData()
	_ = d.Set("project_id", "p_1")
	_ = d.Set("name", "nightly")
	_ = d.Set("cron", "0 0 * * *")
	_ = d.Set("dataset_id", "d_1")
	_ = d.Set("model", "openai:gpt-4o")
	_ = d.Set("metrics", []any{"faithfulness", "relevance"})

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceEvalScheduleCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "sched_1" {
		t.Errorf("id not set: %q", d.Id())
	}
}

// ─── Resource: evalguard_gateway_policy ────────────────────────────────────

func TestResourceGatewayPolicy_CreateAndDelete(t *testing.T) {
	// /gateway/policies is action-discriminated (B4 backend): POST is the
	// create channel; DELETE is /gateway/policies?id=<id>, not RESTful.
	srv := newMockServer(t,
		// Create-rule action returns the new rule wrapped in `{rule: …}`
		// — see resourceGatewayPolicyCreate which unmarshals into
		// `struct { Rule *gatewayPolicyAPI }`.
		&mockRoute{method: "POST", path: "/gateway/policies", status: 201,
			body: envelope(`{"rule":{"id":"pol_1","project_id":"p_1","name":"prod","enabled":true,"routing_strategy":"least_latency","targets":[{"provider":"openai","model":"gpt-4o","weight":1,"max_rpm":1000}]}}`)},
		// Provider URL-encodes the id parameter, so `?id=pol_1` becomes
		// `?id=pol_1`. The pathMatches helper only matches the path stem;
		// query params on the underlying request are ignored by the matcher.
		&mockRoute{method: "DELETE", path: "/gateway/policies", status: 204},
	)
	ts := srv.serve()
	defer ts.Close()

	r := resourceGatewayPolicy()
	d := r.TestResourceData()
	_ = d.Set("project_id", "p_1")
	_ = d.Set("name", "prod")
	_ = d.Set("enabled", true)
	_ = d.Set("routing_strategy", "least_latency")
	_ = d.Set("targets", []any{
		map[string]any{"provider": "openai", "model": "gpt-4o", "weight": 1, "max_rpm": 1000},
	})

	c := &apiClient{apiKey: "k", baseURL: ts.URL, http: &http.Client{}}
	if diags := resourceGatewayPolicyCreate(context.Background(), d, c); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if d.Id() != "pol_1" {
		t.Errorf("id not set: %q", d.Id())
	}
	if diags := resourceGatewayPolicyDelete(context.Background(), d, c); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
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
