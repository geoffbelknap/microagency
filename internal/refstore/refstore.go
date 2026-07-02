// Package refstore stores large results behind opaque reference handles so the
// model receives a <ref_> + summary instead of the raw payload. The in-memory
// MemStore is the v1 stub; a persisted KV (customer-owned at scale) replaces it
// behind this same interface.
package refstore

import "crypto/rand"

// Ref is an opaque handle to a stored payload, formatted like
// "<ref_9fK2c7pQvX3m>" — an unguessable, random token, NOT a sequence number.
type Ref string

// refAlphabet is base62 (no +/=_-): every char is safe in JSON, a URL path, and a
// filename, so a handle maps 1:1 to a store filename with no escaping.
const refAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// refTokenLen is the number of base62 chars in a handle: 12 → ~71 bits of entropy.
// Enough that handles can't be walked or guessed, and collisions are negligible;
// short enough that carrying a ref in model context costs few tokens.
const refTokenLen = 12

// randRef mints a fresh unguessable handle. Random (not sequential) so a handle
// can't be enumerated and one ref never reveals how many others exist — the first
// layer of ref-identity hardening. crypto/rand failure is fatal (fail closed): a
// weak handle must never be issued.
func randRef() Ref {
	out := make([]byte, refTokenLen)
	var b [1]byte
	for i := 0; i < refTokenLen; {
		if _, err := rand.Read(b[:]); err != nil {
			panic("refstore: crypto/rand unavailable: " + err.Error())
		}
		if b[0] >= 248 { // 256 - (256 % 62); reject the top slice to avoid modulo bias
			continue
		}
		out[i] = refAlphabet[b[0]%62]
		i++
	}
	return Ref("<ref_" + string(out) + ">")
}

// refToken returns the inner token of a "<ref_TOKEN>" handle and whether the shape
// is valid. It accepts ONLY <ref_ + base62 + >, so a caller-supplied handle can
// never carry path separators or "..", i.e. can never escape a store directory.
func refToken(ref Ref) (string, bool) {
	s := string(ref)
	if len(s) < len("<ref_>")+1 || s[:len("<ref_")] != "<ref_" || s[len(s)-1] != '>' {
		return "", false
	}
	tok := s[len("<ref_") : len(s)-1]
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return "", false
		}
	}
	return tok, tok != ""
}

// Summary is the non-payload metadata returned to the model when a result is
// reffed: its size. Deliberately no content head: the agent-facing preview is the
// values-free structuralPreview computed at the gateway — a raw-byte head here
// would be a standing invitation to leak payload into context.
type Summary struct {
	Bytes int `json:"bytes"`
}

// Store maps reference handles to payloads.
type Store interface {
	Put(payload string) (Ref, Summary)
	Get(ref Ref) (payload string, ok bool)
}
