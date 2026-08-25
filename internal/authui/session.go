package authui

import (
	"encoding/json"
	"strings"
)

// Browser-storage keys the served pages share.
//
// Sign-in and the account application are two documents on one origin: the
// first writes the tab's access token, the second reads it. They address the
// same key by construction here rather than each spelling a string that can
// drift apart in a later edit.
//
// The names are deliberately generic. Everything in a page served before
// sign-in is published to whoever asks for it, script included, so a key naming
// the product would identify the deployment as surely as a heading would.
// Storage is scoped to one origin, so a generic name collides with nothing.
const (
	// TokenKey holds the access token, in sessionStorage: one tab, gone when
	// that tab closes, never a cookie and never a server-side session.
	TokenKey = "session.token"
	// NoticeKey hands one sentence from the account application back to the
	// sign-in page when a session ends while the page is open.
	NoticeKey = "session.notice"
	// PKCEKey holds the verifier, nonce, and issuer of an authorization code
	// exchange that is in flight, in sessionStorage.
	PKCEKey = "session.pkce"
	// AttemptKey records that the browser left for the authorization server, so
	// returning without a result is distinguishable from never having started.
	AttemptKey = "session.attempt"
	// ClientKey prefixes the dynamically registered client_id, in localStorage:
	// it outlives the tab, and it is per origin because a different origin is a
	// different issuer and therefore a different client.
	ClientKey = "oauth.client:"
)

// SessionKeys is the storage-key set a page receives in its config island, so
// the JavaScript reads the constants above instead of restating them.
type SessionKeys struct {
	Token   string `json:"token"`
	Notice  string `json:"notice"`
	PKCE    string `json:"pkce,omitempty"`
	Attempt string `json:"attempt,omitempty"`
	Client  string `json:"client,omitempty"`
}

// SharedKeys returns the keys both documents use: the token one writes and the
// other reads, and the notice passed back the other way.
func SharedKeys() SessionKeys {
	return SessionKeys{Token: TokenKey, Notice: NoticeKey}
}

// SignInKeys returns SharedKeys plus the three an authorization code exchange
// needs. Only the sign-in page runs that exchange.
func SignInKeys() SessionKeys {
	k := SharedKeys()
	k.PKCE, k.Attempt, k.Client = PKCEKey, AttemptKey, ClientKey
	return k
}

// JSONIsland renders v as an inert JSON island the page parses with JSON.parse.
//
// A value containing "</script" would otherwise end the element early, so every
// HTML-significant character is escaped to its \u form. encoding/json already
// does that for <, >, & and for the line and paragraph separators; the replacer
// states the requirement here so it survives a switch to another encoder.
func JSONIsland(id string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{}`)
	}
	return `<script type="application/json" id="` + id + `">` +
		jsonInScript.Replace(string(b)) + `</script>`
}

var jsonInScript = strings.NewReplacer(
	"<", `\u003c`, ">", `\u003e`, "&", `\u0026`,
	"\u2028", `\u2028`, "\u2029", `\u2029`,
)
