package gitops

import (
	"context"
	"fmt"

	"github.com/go-git/go-billy/v6"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/trublast/vault-plugin-gitops/pkg/engine"
	"github.com/trublast/vault-plugin-gitops/pkg/util"
	"github.com/trublast/vault-plugin-gitops/pkg/vault_client"
)

func init() {
	engine.Register("gitops", &engineImpl{})
}

type engineImpl struct{}

func (e *engineImpl) ProcessCommit(ctx context.Context, storage logical.Storage, worktreeFS billy.Filesystem, logger hclog.Logger) error {
	vaultConfig, err := vault_client.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get vault configuration: %w", err)
	}
	gitopsConfig, err := GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get gitops configuration: %w", err)
	}
	rootPath := ""
	if gitopsConfig != nil {
		rootPath = gitopsConfig.Path
	}

	resources, err := LoadResourcesFromFS(worktreeFS, rootPath)
	if err != nil {
		return fmt.Errorf("unable to load resources from repo: %w", err)
	}
	if err := Lint(resources); err != nil {
		return fmt.Errorf("lint: %w", err)
	}

	var state State
	if err := util.GetJSON(ctx, storage, StorageKeyState, &state); err != nil {
		return fmt.Errorf("unable to load state: %w", err)
	}
	if state.Resources == nil {
		state.Resources = make(map[string]StateResource)
	}

	vaultClient, err := vault_client.NewClientFromConfig(vaultConfig)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}
	writer := NewStorageStateWriter(storage)
	if err := Apply(ctx, resources, vaultClient, &state, writer); err != nil {
		return fmt.Errorf("gitops apply: %w", err)
	}
	return nil
}

func (e *engineImpl) Paths(baseBackend *framework.Backend) []*framework.Path {
	return Paths(baseBackend)
}
