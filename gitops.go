package plugin_gitops

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gitHTTP "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/hashicorp/vault/sdk/logical"

	trdlGit "github.com/trublast/vault-plugin-gitops/pkg/git"
	"github.com/trublast/vault-plugin-gitops/pkg/git_repository"
	"github.com/trublast/vault-plugin-gitops/pkg/gitops"
	"github.com/trublast/vault-plugin-gitops/pkg/util"
	"github.com/trublast/vault-plugin-gitops/pkg/vault_client"
)

// processCommit applies declarative YAML from the repo at the given commit.
func (b *backend) processCommit(ctx context.Context, storage logical.Storage, hashCommit string) error {
	b.Logger().Debug(fmt.Sprintf("Processing commit: %q", hashCommit))

	config, err := git_repository.GetConfig(ctx, storage, b.Logger())
	if err != nil {
		return fmt.Errorf("unable to get git repository configuration: %w", err)
	}

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

	gitRepo, err := b.cloneRepositoryAtCommit(ctx, storage, config, hashCommit)
	if err != nil {
		return fmt.Errorf("unable to clone repository at commit %q: %w", hashCommit, err)
	}
	defer func() { gitRepo = nil }()

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
	writer := &storageStateWriter{storage: storage}
	if err := gitops.Apply(ctx, resources, vaultClient, &state, writer); err != nil {
		return fmt.Errorf("gitops apply: %w", err)
	}

	return nil
}

// cloneRepositoryAtCommit clones repository and checks out to specific commit
func (b *backend) cloneRepositoryAtCommit(ctx context.Context, storage logical.Storage, config *git_repository.Configuration, commitHash string) (*git.Repository, error) {
	gitCredentials, err := trdlGit.GetGitCredential(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get Git credentials: %w", err)
	}

	var cloneOptions trdlGit.CloneOptions
	{
		cloneOptions.BranchName = config.GitBranch
		if gitCredentials != nil && gitCredentials.Username != "" && gitCredentials.Password != "" {
			cloneOptions.Auth = &gitHTTP.BasicAuth{
				Username: gitCredentials.Username,
				Password: gitCredentials.Password,
			}
		}
		if config.GitCACertificate != "" {
			cloneOptions.CABundle = []byte(config.GitCACertificate)
		}
	}

	gitRepo, err := trdlGit.CloneInMemory(config.GitRepoUrl, cloneOptions)
	if err != nil {
		return nil, fmt.Errorf("cloning repository: %w", err)
	}

	// Checkout to specific commit
	worktree, err := gitRepo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	commitHashObj := plumbing.NewHash(commitHash)
	err = worktree.Checkout(&git.CheckoutOptions{
		Hash: commitHashObj,
	})
	if err != nil {
		return nil, fmt.Errorf("checking out commit %q: %w", commitHash, err)
	}

	b.Logger().Debug(fmt.Sprintf("Checked out to commit: %q", commitHash))
	return gitRepo, nil
}
