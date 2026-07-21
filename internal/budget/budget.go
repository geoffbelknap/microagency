// Package budget enforces pass-by-reference: every executor result passes
// through the Gate before it can reach the model. Within budget it is returned
// inline; over budget it is stored behind a ref and only {ref, summary} is
// returned. This is the enforcement point that keeps raw data out of the model.
package budget

import "microagency/internal/refstore"

// Outcome is the result of applying the budget to a payload. Exactly one of
// Inline (Reffed=false) or Ref+Summary (Reffed=true) is meaningful.
type Outcome struct {
	Reffed  bool
	Inline  string
	Ref     refstore.Ref
	Summary refstore.Summary
}

// Gate enforces a byte budget against a RefStore.
type Gate struct {
	MaxBytes int
	Store    refstore.Store
}

// Apply returns the payload inline if it is within MaxBytes (inclusive),
// otherwise stores it and returns a ref + summary.
func (g Gate) Apply(payload, owner string) Outcome {
	if len(payload) <= g.MaxBytes {
		return Outcome{Inline: payload}
	}
	ref, sum := g.Store.Put(payload, owner)
	return Outcome{Reffed: true, Ref: ref, Summary: sum}
}
