// Main workflow of the flant_gitops.
// On each iteration:
// 1. Search from HEAD backwards to last_finished_commit (or initial_last_successful_commit if not set)
// 2. Find the first commit that has the required number of verified signatures
// 3. Call processCommit for that commit
// 4. If processCommit succeeds, save the commit as last_finished_commit
// 5. Next search will be from HEAD to the new last_finished_commit

package plugin_gitops

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/trublast/vault-plugin-gitops/pkg/git_repository"
	"github.com/trublast/vault-plugin-gitops/pkg/util"
)

// for testability
var (
	systemClock util.Clock = util.NewSystemClock()
)

// LastFinishedCommit represents the last successfully processed commit with its date
type LastFinishedCommit struct {
	CommitHash string    `json:"commit_hash"`
	CommitDate time.Time `json:"commit_date"`
}

const (
	storageKeyLastFinishedCommit = "last_processed_commit"
	lastPeriodicRunTimestampKey  = "last_periodic_run_timestamp"
	storageKeyProcessStatus      = "process_status"
)

func (b *backend) PeriodicTask(ctx context.Context, storage logical.Storage) error {

	// Check and update vault token expire time if needed (using vault_client functions)
	// Run asynchronously to avoid blocking PeriodicTask
	go func() {
		token_ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := b.checkAndUpdateVaultTokenExpireTime(token_ctx, storage); err != nil {
			b.Logger().Warn(fmt.Sprintf("Failed to check/update vault token expire time: %v", err))
		}
	}()

	// Check if processGit is already running using CAS guard
	if !atomic.CompareAndSwapUint32(b.processGitCASGuard, 0, 1) {
		b.Logger().Debug("GitOps task already in progress, skipping this iteration")
		return nil
	}

	// Get last finished commit
	var lastFinishedCommit *LastFinishedCommit
	err := util.GetJSON(ctx, storage, storageKeyLastFinishedCommit, &lastFinishedCommit)
	if err != nil {
		return fmt.Errorf("unable to get last finished commit: %w", err)
	}

	// Launch processGit in a goroutine to avoid blocking PeriodicTask
	go b.processGitInternal(storage, lastFinishedCommit)

	return nil
}

// processGitInternal is the internal function that runs in a goroutine
// It ensures the CAS guard is reset when the function completes (successfully or with error)
func (b *backend) processGitInternal(storage logical.Storage, lastFinishedCommit *LastFinishedCommit) {
	defer atomic.StoreUint32(b.processGitCASGuard, 0)

	// Don't cancel when the original client request goes away
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := b.processGit(ctx, storage, lastFinishedCommit); err != nil {
		b.Logger().Warn(fmt.Sprintf("Cant process gitops task: %v", err))
	}
}

func (b *backend) processGit(ctx context.Context, storage logical.Storage, lastFinishedCommit *LastFinishedCommit) error {
	config, err := git_repository.GetConfig(ctx, storage, b.Logger())
	if err != nil {
		return err
	}

	gitCheckintervalExceeded, err := checkExceedingInterval(ctx, storage, config.GitPollPeriod)
	if err != nil {
		return err
	}

	if !gitCheckintervalExceeded {
		b.Logger().Debug("git poll interval not exceeded, finish periodic task")
		return nil
	}

	newTimeStamp := systemClock.Now()
	if err := updateLastRunTimeStamp(ctx, storage, newTimeStamp); err != nil {
		return err
	}

	// Convert LastFinishedCommit to LastFinishedCommitInfo for git_repository
	var lastFinishedCommitInfo *git_repository.CommitInfo
	if lastFinishedCommit != nil {
		lastFinishedCommitInfo = &git_repository.CommitInfo{
			CommitHash: lastFinishedCommit.CommitHash,
			CommitDate: lastFinishedCommit.CommitDate,
		}
	}

	// Clone once; find first signed commit in the same repo, then process it
	gitSvc := git_repository.GitService(ctx, storage, b.Logger())
	gitRepo, _, err := gitSvc.Clone()
	if err != nil {
		storeProcessStatusCommit(ctx, storage, fmt.Sprintf("FAILED check git repo: %s", err.Error()))
		return fmt.Errorf("cloning repository: %w", err)
	}

	commitInfo, err := gitSvc.FindFirstSignedCommitFromRepo(gitRepo, lastFinishedCommitInfo)
	if err != nil {
		storeProcessStatusCommit(ctx, storage, fmt.Sprintf("FAILED check git repo: %s", err.Error()))
		return fmt.Errorf("finding signed commit: %w", err)
	}

	if commitInfo == nil {
		b.Logger().Debug("No signed commit found: finish periodic task")
		// TODO: do not store status when already same status
		if err := storeProcessStatusCommit(ctx, storage, "No new signed commit found"); err != nil {
			return fmt.Errorf("unable to store process status commit: %w", err)
		}
		return nil
	}

	b.Logger().Info("Found signed commit to process", "commitHash", commitInfo.CommitHash, "commitDate", commitInfo.CommitDate)

	storeProcessStatusCommit(ctx, storage, fmt.Sprintf("Processing commit %q", commitInfo.CommitHash))

	err = b.processCommitWithRepo(ctx, storage, gitRepo, commitInfo.CommitHash)
	if err != nil {
		storeProcessStatusCommit(ctx, storage, fmt.Sprintf("FAILED processing commit %q: %s", commitInfo.CommitHash, err.Error()))
		return fmt.Errorf("processing commit %q: %w", commitInfo.CommitHash, err)
	}

	if err := storeProcessStatusCommit(ctx, storage, fmt.Sprintf("Successfully processed commit %q", commitInfo.CommitHash)); err != nil {
		return fmt.Errorf("unable to store process status commit: %w", err)
	}

	// Convert CommitInfo to LastFinishedCommit and save
	lastFinishedCommitToStore := &LastFinishedCommit{
		CommitHash: commitInfo.CommitHash,
		CommitDate: commitInfo.CommitDate,
	}

	// Save last finished commit only if processCommit succeeded
	if err := storeLastFinishedCommit(ctx, storage, lastFinishedCommitToStore); err != nil {
		return fmt.Errorf("unable to save last finished commit: %w", err)
	}

	b.Logger().Info("Successfully processed commit", "commitHash", commitInfo.CommitHash, "commitDate", commitInfo.CommitDate)

	return nil
}

// checkExceedingInterval returns true if more than interval were spent
func checkExceedingInterval(ctx context.Context, storage logical.Storage, interval time.Duration) (bool, error) {
	result := false
	lastRunTimestamp, err := util.GetInt64(ctx, storage, lastPeriodicRunTimestampKey)
	if err != nil {
		return false, err
	}
	if systemClock.Since(time.Unix(lastRunTimestamp, 0)) > interval {
		result = true
	}
	return result, nil
}

func updateLastRunTimeStamp(ctx context.Context, storage logical.Storage, timeStamp time.Time) error {
	return util.PutInt64(ctx, storage, lastPeriodicRunTimestampKey, timeStamp.Unix())
}

func storeLastFinishedCommit(ctx context.Context, storage logical.Storage, commitInfo *LastFinishedCommit) error {
	return util.PutJSON(ctx, storage, storageKeyLastFinishedCommit, commitInfo)
}

func storeProcessStatusCommit(ctx context.Context, storage logical.Storage, status string) error {
	return util.PutString(ctx, storage, storageKeyProcessStatus, status)
}
