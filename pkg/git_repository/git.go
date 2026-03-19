package git_repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	goGit "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	trdlGit "github.com/trublast/vault-plugin-gitops/pkg/git"
	"github.com/trublast/vault-plugin-gitops/pkg/pgp"
)

type gitCommitHash = string

// CommitInfo represents a commit with its hash and date
type CommitInfo struct {
	CommitHash string
	CommitDate time.Time
}

type gitService struct {
	ctx     context.Context
	storage logical.Storage
	logger  hclog.Logger
}

func GitService(ctx context.Context, storage logical.Storage, logger hclog.Logger) gitService {
	return gitService{
		ctx:     ctx,
		storage: storage,
		logger:  logger,
	}
}

// Clone fetches the git repository into memory (branch from config) and returns the repo and HEAD commit hash.
func (g gitService) Clone() (*goGit.Repository, string, error) {
	config, err := GetConfig(g.ctx, g.storage, g.logger)
	if err != nil {
		return nil, "", err
	}
	g.logger.Debug(fmt.Sprintf("Cloning git repo %q branch %q", config.GitRepoUrl, config.GitBranch))
	return g.cloneGit(config)
}

// FindFirstSignedCommitFromRepo searches for the first signed commit in an already-cloned repository,
// from HEAD backwards until lastFinishedCommit.
// Returns the first commit that has the required number of verified signatures.
func (g gitService) FindFirstSignedCommitFromRepo(gitRepo *goGit.Repository, lastFinishedCommit *CommitInfo) (*CommitInfo, error) {
	config, err := GetConfig(g.ctx, g.storage, g.logger)
	if err != nil {
		return nil, err
	}

	boundaryCommit := ""
	if lastFinishedCommit != nil {
		boundaryCommit = lastFinishedCommit.CommitHash
	}

	ref, err := gitRepo.Head()
	if err != nil {
		return nil, fmt.Errorf("unable to get HEAD: %w", err)
	}
	headCommit := ref.Hash().String()

	if boundaryCommit != "" && boundaryCommit == headCommit {
		g.logger.Debug("Head commit equals boundary commit: no new commits to process")
		return nil, nil
	}

	trustedPGPPublicKeys, err := pgp.GetTrustedPGPPublicKeys(g.ctx, g.storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get trusted public keys: %w", err)
	}

	currentTime := time.Now()

	commit, err := gitRepo.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("unable to get HEAD commit object: %w", err)
	}

	commitIter, err := gitRepo.Log(&goGit.LogOptions{From: commit.Hash})
	if err != nil {
		return nil, fmt.Errorf("unable to create commit iterator: %w", err)
	}
	defer commitIter.Close()

	for {
		c, err := commitIter.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error iterating commits: %w", err)
		}

		commitHash := c.Hash.String()
		commitDate := c.Committer.When

		if boundaryCommit != "" && commitHash == boundaryCommit {
			g.logger.Debug(fmt.Sprintf("Reached boundary commit %q, stopping search", boundaryCommit))
			break
		}

		err = trdlGit.VerifyCommitSignatures(gitRepo, commitHash, trustedPGPPublicKeys, config.RequiredNumberOfVerifiedSignaturesOnCommit, g.logger)
		if err != nil {
			g.logger.Debug(fmt.Sprintf("Commit %q does not have required signatures: %s", commitHash, err.Error()))
			continue
		}

		if commitDate.After(currentTime) {
			g.logger.Debug(fmt.Sprintf("Commit %q has date %v which is in the future, skipping", commitHash, commitDate))
			continue
		}

		if lastFinishedCommit != nil && commitDate.Before(lastFinishedCommit.CommitDate) {
			g.logger.Debug(fmt.Sprintf("Commit %q has date %v which is older than last finished commit date %v, skipping", commitHash, commitDate, lastFinishedCommit.CommitDate))
			continue
		}

		g.logger.Info(fmt.Sprintf("Found signed commit: %q with date %v", commitHash, commitDate))
		return &CommitInfo{
			CommitHash: commitHash,
			CommitDate: commitDate,
		}, nil
	}

	g.logger.Debug("No signed commit found in the search range")
	return nil, nil
}

// cloneGit clones specified repo, checkout specified branch and return head commit of branch
func (g gitService) cloneGit(config *Configuration) (*goGit.Repository, gitCommitHash, error) {
	gitCredentials, err := trdlGit.GetGitCredential(g.ctx, g.storage)
	if err != nil {
		return nil, "", fmt.Errorf("unable to get Git credentials Configuration: %s", err)
	}

	cloneOptions := trdlGit.CloneOptions{
		BranchName:        config.GitBranch,
		MaxCloneSizeBytes: config.MaxCloneSizeBytes,
	}
	if gitCredentials != nil && gitCredentials.Username != "" && gitCredentials.Password != "" {
		cloneOptions.Auth = &http.BasicAuth{
			Username: gitCredentials.Username,
			Password: gitCredentials.Password,
		}
	}
	if config.GitCACertificate != "" {
		cloneOptions.CABundle = []byte(config.GitCACertificate)
	}

	var gitRepo *goGit.Repository
	if gitRepo, err = trdlGit.CloneInMemory(config.GitRepoUrl, cloneOptions); err != nil {
		return nil, "", fmt.Errorf("cloning in memory: %w", err)
	}

	r, err := gitRepo.Head()
	if err != nil {
		return nil, "", err
	}
	headCommit := r.Hash().String()
	g.logger.Debug(fmt.Sprintf("Got head commit: %s", headCommit))
	return gitRepo, headCommit, nil
}

func GetConfig(ctx context.Context, storage logical.Storage, logger hclog.Logger) (*Configuration, error) {
	config, err := getConfiguration(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get Configuration: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("Configuration not set")
	}
	return config, nil
}
