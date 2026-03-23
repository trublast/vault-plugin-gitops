package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-git/go-billy/v6"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Engine abstracts a commit-processing backend (gitops, terraform, etc.).
// Implementations self-register via init() so build tags can control which
// engines are compiled into the binary.
type Engine interface {
	ProcessCommit(ctx context.Context, storage logical.Storage, worktreeFS billy.Filesystem, logger hclog.Logger) error
	Paths(baseBackend *framework.Backend) []*framework.Path
}

var (
	mu       sync.RWMutex
	registry = map[string]Engine{}
)

// Register adds an engine under the given name. Intended to be called from init().
func Register(name string, e Engine) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("engine: Register called twice for %q", name))
	}
	registry[name] = e
}

// Get returns a registered engine by name.
func Get(name string) (Engine, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := registry[name]
	return e, ok
}

// RegisteredNames returns the names of all registered engines.
func RegisteredNames() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}
