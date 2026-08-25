package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/auth"
	"microagency/internal/mcp"
	"microagency/internal/portal"
)

func mcpGet(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// The root answers on the public listener, with a sign-in affordance when this
// deployment serves a portal to sign in to.
func TestLandingPageIsServedOnTheAgentPlane(t *testing.T) {
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{addr: "127.0.0.1:8765", authDir: t.TempDir()}
	mcpMux, _, _, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	rec := mcpGet(t, mcpMux, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "microagency") || !strings.Contains(body, portal.Path) {
		t.Error("landing page does not name the product and its sign-in route")
	}
	// It must not shadow anything already mounted on this listener.
	if rec := mcpGet(t, mcpMux, "/.well-known/oauth-authorization-server"); rec.Code != http.StatusOK {
		t.Errorf("OAuth metadata = %d; the landing page must not shadow discovery", rec.Code)
	}
	if rec := mcpGet(t, mcpMux, portal.Path); rec.Code != http.StatusOK {
		t.Errorf("%s = %d; the landing page must not shadow the portal", portal.Path, rec.Code)
	}
	if rec := mcpGet(t, mcpMux, "/nothing-here"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404", rec.Code)
	}
}

// Refusing registration is a declarable posture. The endpoint refuses, the
// metadata stops advertising it, and the account portal — which obtains its own
// client by registering — is not served rather than served broken.
func TestRegistrationOffRefusesAndDropsThePortal(t *testing.T) {
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{addr: "127.0.0.1:8765", authDir: t.TempDir(), clientRegistration: auth.RegistrationOff}
	mcpMux, _, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-local" {
		t.Fatalf("mode = %q", mode)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/register",
		bytes.NewReader([]byte(`{"redirect_uris":["http://127.0.0.1:9999/cb"]}`)))
	req.Header.Set("Content-Type", "application/json")
	mcpMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /oauth/register = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"client_id"`) {
		t.Errorf("a refusing gateway returned a client: %s", rec.Body.String())
	}

	meta := mcpGet(t, mcpMux, "/.well-known/oauth-authorization-server").Body.String()
	if strings.Contains(meta, "registration_endpoint") {
		t.Error("a gateway that refuses registration still advertises a registration endpoint")
	}
	// Discovery must keep working: without it no client can find where to
	// authenticate at all.
	for _, required := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if !strings.Contains(meta, required) {
			t.Errorf("metadata dropped %q", required)
		}
	}
	if rec := mcpGet(t, mcpMux, "/oauth/jwks"); rec.Code != http.StatusOK {
		t.Errorf("/oauth/jwks = %d; key discovery must keep working", rec.Code)
	}

	if rec := mcpGet(t, mcpMux, portal.Path); rec.Code != http.StatusNotFound {
		t.Errorf("%s = %d with registration off, want 404", portal.Path, rec.Code)
	}
	// The landing page still answers, without offering a sign-in that leads
	// nowhere.
	landing := mcpGet(t, mcpMux, "/")
	if landing.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", landing.Code)
	}
	if strings.Contains(landing.Body.String(), portal.Path) {
		t.Error("landing page offers a portal this deployment does not serve")
	}
}

// servesPortal drives the startup banner, so it has to agree with the mount
// condition for the registration posture too, not only for the auth mode.
func TestServesPortalTracksTheRegistrationPosture(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  httpConfig
		want bool
	}{
		{"bounded by default", httpConfig{addr: "127.0.0.1:8765"}, true},
		{"bounded explicitly", httpConfig{addr: "127.0.0.1:8765", clientRegistration: auth.RegistrationBounded}, true},
		{"registration off", httpConfig{addr: "127.0.0.1:8765", clientRegistration: auth.RegistrationOff}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := servesPortal(tc.cfg); got != tc.want {
				t.Fatalf("servesPortal = %v, want %v", got, tc.want)
			}
		})
	}
}

// The banner states who may register beside who may sign in. Stating one and
// not the other answers "who can get in here" wrongly.
func TestBannerStatesTheRegistrationPosture(t *testing.T) {
	var bounded, off bytes.Buffer
	writeRegistrationPosture(&bounded, httpConfig{})
	writeRegistrationPosture(&off, httpConfig{clientRegistration: auth.RegistrationOff})
	if !strings.Contains(bounded.String(), "Registers") || !strings.Contains(bounded.String(), "per source") {
		t.Errorf("bounded banner line does not state the bound: %q", bounded.String())
	}
	if !strings.Contains(off.String(), "Registers") || !strings.Contains(off.String(), "off") {
		t.Errorf("off banner line does not state the posture: %q", off.String())
	}
}

// Doctor states the same posture the banner does, beside the audience.
func TestDoctorStatesTheRegistrationPosture(t *testing.T) {
	for _, tc := range []struct {
		name    string
		posture authPosture
		want    string
	}{
		{"bounded", authPosture{ClientRegistration: "bounded"}, "per source"},
		{"off", authPosture{ClientRegistration: "off"}, "off"},
		{"not recorded", authPosture{}, "not recorded"},
		{"unrecognized", authPosture{ClientRegistration: "wide-open"}, "unrecognized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			reportClientRegistration(&out, tc.posture)
			if !strings.Contains(out.String(), "registers") || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("doctor line %q does not state %q", out.String(), tc.want)
			}
		})
	}
}

// A registration is recorded, with no principal, because there is none — that
// is what makes it worth recording.
func TestRegistrationIsAudited(t *testing.T) {
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{addr: "127.0.0.1:8765", authDir: t.TempDir()}
	mcpMux, _, _, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/register",
		bytes.NewReader([]byte(`{"redirect_uris":["http://127.0.0.1:9999/cb"]}`)))
	req.Header.Set("Content-Type", "application/json")
	mcpMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /oauth/register = %d, want 201", rec.Code)
	}
	records := 0
	for _, run := range srv.RunLog() {
		if run.Kind != "client" {
			continue
		}
		records++
		if run.Tool != auth.RegistrationAccepted {
			t.Errorf("recorded outcome %q, want %q", run.Tool, auth.RegistrationAccepted)
		}
		if run.ClientID == "" {
			t.Error("registration record names no client")
		}
		if run.SourceDigest == "" {
			t.Error("registration record carries no source digest")
		}
		if run.User != "" {
			t.Errorf("an anonymous registration was attributed to %q", run.User)
		}
	}
	if records != 1 {
		t.Fatalf("recorded %d client registrations, want 1", records)
	}
}
