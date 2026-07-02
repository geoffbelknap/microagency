package auth

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourceMetadata serves OAuth 2.0 Protected Resource Metadata
// (RFC 9728) at /.well-known/oauth-protected-resource, so an MCP client
// (Claude/ChatGPT) can discover which authorization server protects this
// resource and start the OAuth flow. resource is this server's identifier (its
// audience); issuers are the trusted authorization-server URLs.
func ProtectedResourceMetadata(resource string, issuers ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 resource,
			"authorization_servers":    issuers,
			"bearer_methods_supported": []string{"header"},
		})
	})
}
