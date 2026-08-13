package mcp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
)

const maxTaskIDBytes = 64

type taskIDContextKey struct{}

// validateTaskID accepts only a short opaque identifier and returns a one-way
// correlation key. The caller-provided value never enters the run log or metrics;
// the restricted alphabet also makes the contract unsuitable for prompts, email
// addresses, bearer tokens, or arbitrary user data while allowing UUIDs/run ids.
func validateTaskID(raw string) (string, error) {
	id := strings.TrimSpace(raw)
	if id == "" {
		return "", nil
	}
	if len(id) > maxTaskIDBytes {
		return "", fmt.Errorf("task_id must be at most %d bytes", maxTaskIDBytes)
	}
	for i, r := range id {
		alphanumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		valid := alphanumeric || strings.ContainsRune("._:-", r)
		if !valid || i == 0 && !alphanumeric {
			return "", fmt.Errorf("task_id must start with a letter or digit and contain only letters, digits, '.', '_', ':', or '-'")
		}
	}
	digest := sha256.Sum256([]byte(id))
	return fmt.Sprintf("task_%x", digest[:16]), nil
}

func withTaskID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, taskIDContextKey{}, id)
}

func taskIDOf(ctx context.Context) string {
	id, _ := ctx.Value(taskIDContextKey{}).(string)
	return id
}
