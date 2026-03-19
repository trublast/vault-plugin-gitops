package plugin_gitops

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/trublast/vault-plugin-gitops/pkg/gitops"
	"github.com/trublast/vault-plugin-gitops/pkg/terraform"
	"github.com/trublast/vault-plugin-gitops/pkg/util"
	"github.com/trublast/vault-plugin-gitops/pkg/vault_client"
)

// processCommitWithRepo checkouts the repository to the given commit and runs Terraform or GitOps.
func (b *backend) processCommitWithRepo(ctx context.Context, storage logical.Storage, gitRepo *git.Repository, commitHash string) error {
	if err := b.checkoutRepoToCommit(gitRepo, commitHash); err != nil {
		return err
	}
	return b.processCommitWithRepoAtHead(ctx, storage, gitRepo)
}

// processCommitWithRepoAtHead runs Terraform or GitOps on the repo (worktree must already be at the desired commit).
func (b *backend) processCommitWithRepoAtHead(ctx context.Context, storage logical.Storage, gitRepo *git.Repository) error {
	switch b.engineMode {
	case EngineModeTerraform:
		return b.processCommitTerraform(ctx, storage, gitRepo)
	default:
		return b.processCommitGitOps(ctx, storage, gitRepo)
	}
}

// checkoutRepoToCommit checkouts the repository worktree to the given commit.
func (b *backend) checkoutRepoToCommit(gitRepo *git.Repository, commitHash string) error {
	worktree, err := gitRepo.Worktree()
	if err != nil {
		return fmt.Errorf("getting worktree: %w", err)
	}
	commitHashObj := plumbing.NewHash(commitHash)
	if err := worktree.Checkout(&git.CheckoutOptions{Hash: commitHashObj}); err != nil {
		return fmt.Errorf("checking out commit %q: %w", commitHash, err)
	}
	b.Logger().Debug(fmt.Sprintf("Checked out to commit: %q", commitHash))
	return nil
}

// processCommitTerraform runs Terraform from the cloned repo.
func (b *backend) processCommitTerraform(ctx context.Context, storage logical.Storage, gitRepo *git.Repository) error {
	vaultConfig, err := vault_client.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get vault configuration: %w", err)
	}
	if vaultConfig == nil || vaultConfig.VaultToken == "" {
		return fmt.Errorf("vault configuration is required for terraform mode (configure vault token)")
	}
	tfConfig, err := terraform.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get terraform configuration: %w", err)
	}
	terraformConfig := terraform.CLIConfig{
		VaultAddr:      vaultConfig.VaultAddr,
		VaultToken:     vaultConfig.VaultToken,
		VaultNamespace: vaultConfig.VaultNamespace,
		TfPath:         tfConfig.TfPath,
		TfBinary:       tfConfig.TfBinary,
		TfBinarySHA256: tfConfig.TfBinarySHA256,
		Storage:        storage,
		Logger:         b.Logger(),
	}
	if err := terraform.ApplyTerraformFromRepo(ctx, gitRepo, terraformConfig); err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}
	return nil
}

// processCommitGitOps loads YAML from the cloned repo and applies to Vault API.
func (b *backend) processCommitGitOps(ctx context.Context, storage logical.Storage, gitRepo *git.Repository) error {
	vaultConfig, err := vault_client.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get vault configuration: %w", err)
	}
	gitopsConfig, err := gitops.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get gitops configuration: %w", err)
	}
	rootPath := ""
	if gitopsConfig != nil {
		rootPath = gitopsConfig.Path
	}

	resources, err := gitops.LoadResourcesFromRepo(gitRepo, rootPath)
	if err != nil {
		return fmt.Errorf("unable to load resources from repo: %w", err)
	}
	if err := gitops.Lint(resources); err != nil {
		return fmt.Errorf("lint: %w", err)
	}

	var state gitops.State
	if err := util.GetJSON(ctx, storage, gitops.StorageKeyState, &state); err != nil {
		return fmt.Errorf("unable to load state: %w", err)
	}
	if state.Resources == nil {
		state.Resources = make(map[string]gitops.StateResource)
	}

	vaultClient, err := vault_client.NewClientFromConfig(vaultConfig)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}
	writer := gitops.NewStorageStateWriter(storage)
	if err := gitops.Apply(ctx, resources, vaultClient, &state, writer); err != nil {
		return fmt.Errorf("gitops apply: %w", err)
	}
	return nil
}
