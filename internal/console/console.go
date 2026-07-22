// Package console serves microagency's single-page operator console. It's its own
// package — not part of the MCP protocol package — because it's a self-contained,
// no-build-step web asset that only talks to the token-gated /admin/* API; keeping
// the 64 KB embedded page and its handler out of the gateway core is what lets the
// console evolve without churning the protocol package.
package console

import (
	"bytes"
	_ "embed"
	"net"
	"net/http"
	"strconv"
)

//go:embed console.html
var consoleHTML []byte

// Handler serves the single-page operator console — vanilla HTML/JS, no framework,
// no build step. Every data call it makes hits the token-gated /admin/* API. On a
// LOOPBACK request it injects the operator token so the console authenticates
// itself (the local operator can already read ~/.microagency/token, so this leaks
// nothing new); off loopback it serves the static page and the operator pastes the
// token. token may be "" (no auto-auth).
func Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/console" && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if token != "" && isLoopbackAddr(r.RemoteAddr) {
			inj := []byte("<script>try{localStorage.setItem('microagency.token'," + strconv.Quote(token) + ")}catch(e){}</script></head>")
			_, _ = w.Write(bytes.Replace(consoleHTML, []byte("</head>"), inj, 1))
			return
		}
		_, _ = w.Write(consoleHTML)
	})
}

func isLoopbackAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
