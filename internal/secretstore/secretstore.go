// Package secretstore persists the small secrets microagency *acquires* — OAuth
// refresh-token records for aggregated upstreams — OUTSIDE microagency: in
// OpenBao/Vault (KV v2) when configured, otherwise a 0600 file. When a vault is
// present microagency holds no durable secret itself; it reads the refresh token
// only to mint a fresh access token. (This is the write side; microagent's secret
// resolver is the read side for operator-placed `vault:` refs.)
package secretstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrNotFound is returned by Load when the key is absent.
var ErrNotFound = errors.New("secretstore: not found")

// Store persists secret blobs by key.
type Store interface {
	Save(ctx context.Context, key string, value []byte) error
	Load(ctx context.Context, key string) ([]byte, error) // ErrNotFound if absent
	Delete(ctx context.Context, key string) error
	Kind() string // "vault" | "file"
}

// Open returns a Vault-backed store when VAULT_ADDR + VAULT_TOKEN are set (the
// preferred path), otherwise a 0600 JSON file under dir.
func Open(dir string, getenv func(string) string, client *http.Client) Store {
	if client == nil {
		client = http.DefaultClient
	}
	if addr, tok := getenv("VAULT_ADDR"), getenv("VAULT_TOKEN"); addr != "" && tok != "" {
		mount := getenv("VAULT_MOUNT")
		if mount == "" {
			mount = "secret" // OpenBao/Vault dev default KV v2 mount
		}
		return &Vault{Addr: addr, Token: tok, Mount: mount, Prefix: "microagency", Client: client}
	}
	return &File{Path: filepath.Join(dir, "upstream-tokens.json")}
}

// --- Vault / OpenBao (KV v2) ---

type Vault struct {
	Addr, Token, Mount, Prefix string
	Client                     *http.Client
}

func (v *Vault) Kind() string { return "vault" }

func (v *Vault) dataURL(key string) string {
	return strings.TrimRight(v.Addr, "/") + "/v1/" + v.Mount + "/data/" + v.Prefix + "/" + key
}
func (v *Vault) metaURL(key string) string {
	return strings.TrimRight(v.Addr, "/") + "/v1/" + v.Mount + "/metadata/" + v.Prefix + "/" + key
}

func (v *Vault) do(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return v.Client.Do(req)
}

func (v *Vault) Save(ctx context.Context, key string, value []byte) error {
	body, _ := json.Marshal(map[string]any{"data": map[string]string{"v": string(value)}})
	resp, err := v.do(ctx, http.MethodPost, v.dataURL(key), body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("vault save %q: http %d: %s", key, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (v *Vault) Load(ctx context.Context, key string) ([]byte, error) {
	resp, err := v.do(ctx, http.MethodGet, v.dataURL(key), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("vault load %q: http %d: %s", key, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Data struct {
			Data struct {
				V string `json:"v"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Data.Data.V == "" {
		return nil, ErrNotFound
	}
	return []byte(out.Data.Data.V), nil
}

func (v *Vault) Delete(ctx context.Context, key string) error {
	resp, err := v.do(ctx, http.MethodDelete, v.metaURL(key), nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// --- File fallback (0600 JSON) ---

type File struct {
	Path string
	mu   sync.Mutex
}

func (f *File) Kind() string { return "file" }

func (f *File) read() (map[string]string, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (f *File) write(m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(m)
	return os.WriteFile(f.Path, b, 0o600)
}

func (f *File) Save(_ context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.read()
	if err != nil {
		return err
	}
	m[key] = string(value)
	return f.write(m)
}

func (f *File) Load(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.read()
	if err != nil {
		return nil, err
	}
	v, ok := m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return []byte(v), nil
}

func (f *File) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.read()
	if err != nil {
		return err
	}
	delete(m, key)
	return f.write(m)
}
