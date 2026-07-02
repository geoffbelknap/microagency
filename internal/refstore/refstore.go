// Package refstore stores large results behind opaque reference handles so the
// model receives a <ref_> + summary instead of the raw payload. The in-memory
// MemStore is the v1 stub; a persisted KV (customer-owned at scale) replaces it
// behind this same interface.
package refstore

// Ref is an opaque handle to a stored payload, formatted like "<ref_1>".
type Ref string

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
