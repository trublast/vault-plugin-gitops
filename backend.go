package plugin_gitops

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/trublast/vault-plugin-gitops/pkg/git"
	"github.com/trublast/vault-plugin-gitops/pkg/git_repository"
	"github.com/trublast/vault-plugin-gitops/pkg/gitops"
	"github.com/trublast/vault-plugin-gitops/pkg/pgp"
	"github.com/trublast/vault-plugin-gitops/pkg/util"
	"github.com/trublast/vault-plugin-gitops/pkg/vault_client"
)

// Linker-provided project/build information.
var projectVersion string

type backend struct {
	*framework.Backend

	// Vault token expire time stored in memory (not in storage)
	vaultTokenTTL         *vault_client.TokenTTL
	vaultTokenExpireMutex sync.RWMutex

	// Guard to prevent concurrent execution of processGit
	processGitCASGuard *uint32
}

var _ logical.Factory = Factory

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend(conf)
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("Configuration passed into backend is nil")
	}

	if err := b.SetupBackend(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend(c *logical.BackendConfig) (*backend, error) {
	b := &backend{
		processGitCASGuard: new(uint32),
	}

	baseBackend := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,

		PeriodicFunc: func(ctx context.Context, req *logical.Request) error {
			return b.PeriodicTask(req.Storage)
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				vault_client.StorageKeyConfiguration,
				git.StorageKeyConfigurationGitCredential,
			},
		},
		RunningVersion: projectVersion,
	}

	baseBackend.Paths = framework.PathAppend(
		git_repository.Paths(baseBackend),
		vault_client.Paths(baseBackend),
		gitops.Paths(baseBackend),
		git.CredentialsPaths(),
		pgp.Paths(),
		[]*framework.Path{
			{
				Pattern: "status",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathStatusRead,
						Summary:  "Read the current status",
					},
				},
			},
		},
	)

	b.Backend = baseBackend

	return b, nil
}

func (b *backend) pathStatusRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("Reading git repository configuration")

	status, err := util.GetString(ctx, req.Storage, storageKeyProcessStatus)
	if err != nil {
		return logical.ErrorResponse("Unable to get status: %s", err), nil
	}
	var lastFinishedCommit *LastFinishedCommit
	err = util.GetJSON(ctx, req.Storage, storageKeyLastFinishedCommit, &lastFinishedCommit)
	if err != nil {
		return logical.ErrorResponse("Unable to get commit: %s", err), nil
	}
	lastRunTimestamp, err := util.GetInt64(ctx, req.Storage, lastPeriodicRunTimestampKey)
	if err != nil {
		return logical.ErrorResponse("Unable to get run timastamp: %s", err), nil
	}
	last_run := "never"
	if lastRunTimestamp > 0 {
		last_run = time.Unix(lastRunTimestamp, 0).Format(time.RFC3339)
	}

	responseData := map[string]interface{}{
		"status":   status,
		"last_run": last_run,
	}
	if lastFinishedCommit != nil {
		responseData["last_finished_commit"] = lastFinishedCommit.CommitHash
		responseData["last_finished_commit_date"] = lastFinishedCommit.CommitDate.Format(time.RFC3339)
	} else {
		responseData["last_finished_commit"] = ""
		responseData["last_finished_commit_date"] = ""
	}

	return &logical.Response{Data: responseData}, nil
}

func (b *backend) SetupBackend(ctx context.Context, config *logical.BackendConfig) error {
	if err := b.Setup(ctx, config); err != nil {
		return err
	}
	return nil
}

// initializeVaultTokenExpireTime performs lookup-self and stores expire time in backend
func (b *backend) initializeVaultTokenTTL(ctx context.Context, storage logical.Storage) error {
	vaultConfig, err := vault_client.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get valid vault configuration: %w", err)
	}

	ttl, err := vault_client.LookupTokenSelf(ctx, vaultConfig, b.Logger())
	if err != nil {
		return fmt.Errorf("unable to lookup token: %w", err)
	}

	b.updateVaultTokenTTL(ttl)
	b.Logger().Info(fmt.Sprintf("Initialized vault token expire time: %v", ttl.ExpireTime))
	return nil
}

// checkAndUpdateVaultTokenExpireTime checks if expire time needs to be updated and renews token if needed
func (b *backend) checkAndUpdateVaultTokenExpireTime(ctx context.Context, storage logical.Storage) error {
	// Get vault configuration
	vaultConfig, err := vault_client.GetConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("unable to get valid vault configuration: %w", err)
	}

	// Get current expire time from backend
	ttl := b.getVaultTokenTTL()

	if ttl == nil || ttl.ExpireTime.IsZero() {
		// Expire time not initialized yet, try to initialize
		return b.initializeVaultTokenTTL(ctx, storage)
	}

	// No updates needed if TTL is 0
	if ttl.TTL == 0 {
		return nil
	}

	// Check if token has already expired
	if ttl.ExpireTime.Before(time.Now()) {
		b.Logger().Warn(fmt.Sprintf("Token has already expired (expired at: %v), cannot renew", ttl.ExpireTime))
		return nil
	}

	// Check if expire time is less than 24 hours from now
	oneDay := 24 * time.Hour
	remainingTime := time.Until(ttl.ExpireTime)

	if remainingTime < oneDay {
		b.Logger().Info(fmt.Sprintf("Token expire time is less than 24 hours (remaining: %v), renewing", remainingTime))

		// Renew token using vault_client function
		newTTL, err := vault_client.RenewTokenSelf(ctx, vaultConfig, b.Logger())
		if err != nil {
			return fmt.Errorf("unable to renew token: %w", err)
		}

		// Update expire time in backend
		b.updateVaultTokenTTL(newTTL)
		b.Logger().Info(fmt.Sprintf("Token renewed successfully, new expire time: %v", newTTL.ExpireTime))
	} else {
		b.Logger().Debug(fmt.Sprintf("Token expire time is OK (remaining: %v)", remainingTime))
	}

	return nil
}

// updateVaultTokenExpireTime updates stored expire time (called after renew or lookup)
func (b *backend) updateVaultTokenTTL(ttl *vault_client.TokenTTL) {
	b.vaultTokenExpireMutex.Lock()
	defer b.vaultTokenExpireMutex.Unlock()
	b.vaultTokenTTL = ttl
}

// getVaultTokenExpireTime returns current expire time
func (b *backend) getVaultTokenTTL() *vault_client.TokenTTL {
	b.vaultTokenExpireMutex.RLock()
	defer b.vaultTokenExpireMutex.RUnlock()
	return b.vaultTokenTTL
}

const (
	backendHelp = `
The gitops plugin starts an operator which waits for new commits in the configured git repository, verifies commit signatures by configured pgp keys, then executes configured commands in this new commit.
`
)
