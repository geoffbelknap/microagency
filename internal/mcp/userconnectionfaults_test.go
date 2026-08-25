package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readFault decodes the /connections failure envelope from a response.
func readFault(t *testing.T, resp *http.Response) connectionFault {
	t.Helper()
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("refusal content-type = %q, want JSON; a client cannot branch on prose", ct)
	}
	var fault connectionFault
	if err := json.NewDecoder(resp.Body).Decode(&fault); err != nil {
		t.Fatalf("decode fault: %v", err)
	}
	if fault.Kind == "" || fault.Message == "" || fault.Actor == "" {
		t.Fatalf("incomplete fault %+v: every refusal states its kind, its message, and who can act", fault)
	}
	return fault
}

// publishTemplate publishes one connection template on the operator surface.
func publishTemplate(t *testing.T, fixture *selfServiceFixture, id, upstreamURL string) {
	t.Helper()
	body := `{"id":"` + id + `","display_name":"` + id + `","url":"` + upstreamURL + `","max_per_user":2}`
	if rec := adminReq(t, fixture.admin, http.MethodPost, "/admin/connection-templates", "operator", body); rec.Code != http.StatusOK {
		t.Fatalf("publish %s: %d %s", id, rec.Code, rec.Body.String())
	}
}

// connectionEvents returns the audit records for one connection lifecycle action.
func connectionEvents(server *Server, action string) []RunInfo {
	var out []RunInfo
	for _, event := range server.RunLog() {
		if event.Kind == "connection" && event.Tool == action {
			out = append(out, event)
		}
	}
	return out
}

// A provider the gateway cannot reach is a connectivity failure, not a statement
// about what that provider supports. Reporting it as "does not advertise OAuth"
// sends an operator to look at a provider's OAuth configuration when the
// provider was never reached, and tells a user a retry is pointless when it is
// the one thing that might work.
func TestUnreachableProviderIsNotReportedAsMissingOAuth(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens here now, so the probe cannot dial
	publishTemplate(t, fixture, "offline", deadURL)

	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice",
		map[string]any{"template": "offline"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	fault := readFault(t, resp)
	if fault.Kind != faultTransient || !fault.Retryable {
		t.Errorf("unreachable provider classified %+v; a dial failure is transient and retryable", fault)
	}
	if strings.Contains(fault.Message, "advertise") {
		t.Errorf("message %q describes the provider's OAuth support; it was never reached", fault.Message)
	}
	if !strings.Contains(fault.Message, "reach") {
		t.Errorf("message %q does not say the provider could not be reached", fault.Message)
	}
}

// An upstream that answers but names no protected-resource metadata genuinely
// does not do OAuth. That one IS a statement about the provider, and it is the
// operator's template to fix.
func TestProviderWithoutOAuthIsAnOperatorFault(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(plain.Close)
	publishTemplate(t, fixture, "plain", plain.URL)

	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice",
		map[string]any{"template": "plain"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	fault := readFault(t, resp)
	if fault.Kind != faultUnsupported || fault.Actor != actorOperator || fault.Retryable {
		t.Errorf("no-OAuth provider classified %+v; want an unsupported operator fault that is not retryable", fault)
	}
}

// The reported case: a provider whose authorization server publishes no
// registration_endpoint, so the gateway cannot register itself and the template
// needs an operator-configured client. Nothing the user does changes it, so the
// refusal must not be retryable and must name the operator as the actor.
func TestProviderWithoutDynamicRegistrationIsAnOperatorFault(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	publishTemplate(t, fixture, "nodcr", noDCRUpstream(t))

	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice",
		map[string]any{"template": "nodcr"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	fault := readFault(t, resp)
	if fault.Kind != faultUnsupported || fault.Actor != actorOperator || fault.Retryable {
		t.Errorf("no-DCR provider classified %+v; want an unsupported operator fault that is not retryable", fault)
	}
	// The operator console's remediation is written for an operator adding a
	// connection. It must not be handed to whoever clicked connect.
	if strings.Contains(fault.Message, "adding the connection") {
		t.Errorf("message %q hands a user the operator console's remediation", fault.Message)
	}
}

// A failed start is the evidence that a template is misconfigured. Before this,
// a template that refused every attempt produced no audit record at all, so an
// operator inspecting the deployment saw nothing.
func TestFailedConnectionStartIsAudited(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	publishTemplate(t, fixture, "nodcr", noDCRUpstream(t))

	if before := connectionEvents(fixture.server, "authorization_start_failed"); len(before) != 0 {
		t.Fatalf("audit already carried %d failed starts", len(before))
	}
	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice",
		map[string]any{"template": "nodcr"})
	resp.Body.Close()

	events := connectionEvents(fixture.server, "authorization_start_failed")
	if len(events) != 1 {
		t.Fatalf("audit carried %d failed starts, want 1", len(events))
	}
	event := events[0]
	if event.User != pk("alice") {
		t.Errorf("failed start recorded user %q, want %q", event.User, pk("alice"))
	}
	if !strings.HasPrefix(event.Upstream, "nodcr-") {
		t.Errorf("failed start recorded upstream %q; it must name the attempted connection", event.Upstream)
	}
	if event.Outcome != faultUnsupported {
		t.Errorf("failed start recorded outcome %q, want %q", event.Outcome, faultUnsupported)
	}
	if event.OutcomeDetail == "" {
		t.Error("failed start recorded no diagnosis; an operator cannot tell which template is broken")
	}
}

// A successful start still records what it always did. Adding the failure record
// must not change the shape of the record beside it.
func TestSuccessfulConnectionStartStillAudited(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice",
		map[string]any{"template": "documents"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	events := connectionEvents(fixture.server, "authorization_started")
	if len(events) != 1 {
		t.Fatalf("audit carried %d started events, want 1", len(events))
	}
	if events[0].Outcome != "" || events[0].OutcomeDetail != "" {
		t.Errorf("a successful start carried a failure outcome: %+v", events[0])
	}
}

// Every refusal on this API carries the envelope, so a client never has to guess
// whether a body is a classification or a sentence.
func TestUserConnectionRefusalsAreStructured(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	cases := []struct {
		name   string
		method string
		path   string
		body   any
		status int
		kind   string
		actor  string
	}{
		{"unknown template", http.MethodPost, "/connections", map[string]any{"template": "nope"}, http.StatusNotFound, faultNotFound, actorOperator},
		{"bad label", http.MethodPost, "/connections", map[string]any{"template": "documents", "label": strings.Repeat("x", 200)}, http.StatusBadRequest, faultValidation, actorUser},
		{"unknown connection", http.MethodDelete, "/connections/missing", nil, http.StatusNotFound, faultNotFound, actorUser},
		{"refresh unknown", http.MethodPost, "/connections/missing/refresh", nil, http.StatusNotFound, faultNotFound, actorUser},
		{"reauthorize unknown", http.MethodPost, "/connections/missing/reauthorize", map[string]any{}, http.StatusNotFound, faultNotFound, actorUser},
		{"label unknown", http.MethodPatch, "/connections/missing", map[string]any{"label": "x"}, http.StatusNotFound, faultNotFound, actorUser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := userRequest(t, http.DefaultClient, tc.method, fixture.users.URL+tc.path, "alice", tc.body)
			if resp.StatusCode != tc.status {
				defer resp.Body.Close()
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			fault := readFault(t, resp)
			if fault.Kind != tc.kind || fault.Actor != tc.actor {
				t.Errorf("fault = %+v, want kind %q actor %q", fault, tc.kind, tc.actor)
			}
		})
	}
}
