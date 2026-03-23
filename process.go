package plugin_gitops

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/hashicorp/vault/sdk/logical"
)

// processCommitWithRepo checkouts the repository to the given commit and runs the active engine.
func (b *backend) processCommitWithRepo(ctx context.Context, storage logical.Storage, gitRepo *git.Repository, commitHash string) error {
	if err := b.checkoutRepoToCommit(gitRepo, commitHash); err != nil {
		return err
	}
	return b.processCommitWithRepoAtHead(ctx, storage, gitRepo)
}

// processCommitWithRepoAtHead delegates to the active engine (worktree must already be at the desired commit).
func (b *backend) processCommitWithRepoAtHead(ctx context.Context, storage logical.Storage, gitRepo *git.Repository) error {
	wt, err := gitRepo.Worktree()
	if err != nil {
		return fmt.Errorf("getting worktree: %w", err)
	}
	return b.engine.ProcessCommit(ctx, storage, wt.Filesystem, b.Logger())
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
