//go:build linux

package terraform

import (
	"context"
	"fmt"

	"github.com/go-git/go-billy/v6"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/trublast/vault-plugin-gitops/pkg/engine"
	"github.com/trublast/vault-plugin-gitops/pkg/vault_client"
)

func init() {
	engine.Register("terraform", &engineImpl{})
}

type engineImpl struct{}

func (e *engineImpl) ProcessCommit(ctx context.Context, storage logical.Storage, worktreeFS billy.Filesystem, logger hclog.Logger) error {
	vaultConfig, err := vault_client.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get vault configuration: %w", err)
	}
	if vaultConfig == nil || vaultConfig.VaultToken == "" {
		return fmt.Errorf("vault configuration is required for terraform mode (configure vault token)")
	}
	tfConfig, err := GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get terraform configuration: %w", err)
	}
	cliCfg := CLIConfig{
		VaultAddr:      vaultConfig.VaultAddr,
		VaultToken:     vaultConfig.VaultToken,
		VaultNamespace: vaultConfig.VaultNamespace,
		TfPath:         tfConfig.TfPath,
		TfBinary:       tfConfig.TfBinary,
		TfBinarySHA256: tfConfig.TfBinarySHA256,
		Storage:        storage,
		Logger:         logger,
	}
	if err := ApplyTerraformFromFS(ctx, worktreeFS, cliCfg); err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}
	return nil
}

func (e *engineImpl) Paths(baseBackend *framework.Backend) []*framework.Path {
	return Paths(baseBackend)
}
