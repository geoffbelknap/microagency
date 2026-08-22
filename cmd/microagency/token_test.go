package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/optoken"
)

func testTokenStore(t *testing.T) *optoken.Store {
	t.Helper()
	return optoken.NewStore(filepath.Join(t.TempDir(), "operator-tokens.json"))
}

// TestTokenCreatePrintsValueOnceOnStdout pins the capture contract: stdout is
// exactly the secret (script-capturable), the human framing goes to stderr.
func TestTokenCreatePrintsValueOnceOnStdout(t *testing.T) {
	store := testTokenStore(t)
	var stdout, stderr strings.Builder
	if err := runTokenCreate(store, []string{"ci", "--role", "auditor"}, &stdout, &stderr); err != nil {
		t.Fatalf("create: %v", err)
	}
	secret := strings.TrimSpace(stdout.String())
	if secret == "" || strings.ContainsAny(secret, " \n") {
		t.Fatalf("stdout is not exactly the token value: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "shown once") {
		t.Errorf("stderr lost the one-time warning: %q", stderr.String())
	}
	if _, ok := store.Authenticate(secret, time.Now()); !ok {
		t.Fatal("printed value does not authenticate")
	}
}

func TestTokenCreateRequiresRole(t *testing.T) {
	store := testTokenStore(t)
	var stdout, stderr strings.Builder
	err := runTokenCreate(store, []string{"ci"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--role is required") {
		t.Fatalf("create without --role: err = %v", err)
	}
}

func TestTokenCreateDuplicateSuggestsRotate(t *testing.T) {
	store := testTokenStore(t)
	var out, errw strings.Builder
	if err := runTokenCreate(store, []string{"ci", "--role", "admin"}, &out, &errw); err != nil {
		t.Fatal(err)
	}
	err := runTokenCreate(store, []string{"ci", "--role", "admin"}, &out, &errw)
	if err == nil || !strings.Contains(err.Error(), "token rotate ci") {
		t.Fatalf("duplicate create should point at rotate, got: %v", err)
	}
}

func TestTokenListShowsMetadataNeverValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no legacy token file in this HOME
	store := testTokenStore(t)
	var out, errw strings.Builder
	if err := runTokenCreate(store, []string{"ci", "--role", "auditor", "--expires", "30d"}, &out, &errw); err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimSpace(out.String())

	var list strings.Builder
	if err := runTokenList(store, nil, &list); err != nil {
		t.Fatal(err)
	}
	got := list.String()
	if !strings.Contains(got, "ci") || !strings.Contains(got, "auditor") {
		t.Fatalf("list lost name/role:\n%s", got)
	}
	if strings.Contains(got, secret) {
		t.Fatal("list printed a token value")
	}
	if !strings.Contains(got, "EXPIRES") {
		t.Fatalf("list lost the expiry column:\n%s", got)
	}
}

func TestTokenListEmptyStateNamesTheAction(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var list strings.Builder
	if err := runTokenList(testTokenStore(t), nil, &list); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list.String(), "microagency token create") {
		t.Fatalf("empty state does not name the next action:\n%s", list.String())
	}
}

func TestTokenRotateAndRevoke(t *testing.T) {
	store := testTokenStore(t)
	var out, errw strings.Builder
	if err := runTokenCreate(store, []string{"ops", "--role", "admin"}, &out, &errw); err != nil {
		t.Fatal(err)
	}
	old := strings.TrimSpace(out.String())

	var rotOut, rotErr strings.Builder
	if err := runTokenRotate(store, []string{"ops"}, &rotOut, &rotErr); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	fresh := strings.TrimSpace(rotOut.String())
	if fresh == old {
		t.Fatal("rotate did not change the value")
	}
	if _, ok := store.Authenticate(old, time.Now()); ok {
		t.Fatal("old value survives rotate")
	}

	var revErr strings.Builder
	if err := runTokenRevoke(store, []string{"ops"}, &revErr); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := store.Authenticate(fresh, time.Now()); ok {
		t.Fatal("value survives revoke")
	}
	if err := runTokenRevoke(store, []string{"ops"}, &revErr); err == nil {
		t.Fatal("revoking an unknown token succeeded")
	}
}

func TestParseExpires(t *testing.T) {
	if got, err := parseExpires(""); got != nil || err != nil {
		t.Fatalf("empty = %v, %v", got, err)
	}
	before := time.Now().Add(29*24*time.Hour + 23*time.Hour)
	got, err := parseExpires("30d")
	if err != nil || got == nil || got.Before(before) {
		t.Fatalf("30d = %v, %v", got, err)
	}
	if _, err := parseExpires("72h"); err != nil {
		t.Fatalf("72h: %v", err)
	}
	for _, bad := range []string{"0d", "-3h", "soon", "1w"} {
		if _, err := parseExpires(bad); err == nil {
			t.Errorf("parseExpires(%q) accepted", bad)
		}
	}
}
