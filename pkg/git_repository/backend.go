package git_repository

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/structs"
	"github.com/go-git/go-git/v6/plumbing/transport"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	FieldNameGitRepoUrl                                 = "git_repo_url"
	FieldNameGitCACertificate                           = "git_ca_certificate"
	FieldNameGitBranch                                  = "git_branch_name"
	FieldNameGitPollPeriod                              = "git_poll_period"
	FieldNameRequiredNumberOfVerifiedSignaturesOnCommit = "required_number_of_verified_signatures_on_commit"
	FieldNameMaxCloneSizeBytes                          = "max_clone_size_bytes"

	StorageKeyConfiguration = "git_repository_configuration"
)

type Configuration struct {
	GitRepoUrl                                 string        `structs:"git_repo_url" json:"git_repo_url"`
	GitCACertificate                           string        `structs:"git_ca_certificate" json:"git_ca_certificate,omitempty"`
	GitBranch                                  string        `structs:"git_branch_name" json:"git_branch_name"`
	GitPollPeriod                              time.Duration `structs:"git_poll_period" json:"git_poll_period"`
	RequiredNumberOfVerifiedSignaturesOnCommit int           `structs:"required_number_of_verified_signatures_on_commit" json:"required_number_of_verified_signatures_on_commit"`
	MaxCloneSizeBytes                          int64         `structs:"max_clone_size_bytes" json:"max_clone_size_bytes,omitempty"`
}

type backend struct {
	// just for logger provider
	baseBackend *framework.Backend
}

func (b *backend) Logger() hclog.Logger {
	return b.baseBackend.Logger()
}

func Paths(baseBackend *framework.Backend) []*framework.Path {
	b := backend{
		baseBackend: baseBackend,
	}

	return []*framework.Path{
		{
			Pattern: "^configure/git_repository/?$",
			Fields: map[string]*framework.FieldSchema{
				FieldNameGitRepoUrl: {
					Type:        framework.TypeString,
					Description: "Git repo URL. Required for CREATE.",
				},
				FieldNameGitCACertificate: {
					Type:        framework.TypeString,
					Description: "Git CA. Default is empty.",
				},
				FieldNameGitBranch: {
					Type:        framework.TypeString,
					Default:     "main",
					Description: "Git repo branch",
				},
				FieldNameGitPollPeriod: {
					Type:        framework.TypeDurationSecond,
					Default:     "5m",
					Description: "Period between polls of Git repo",
				},
				FieldNameRequiredNumberOfVerifiedSignaturesOnCommit: {
					Type:        framework.TypeInt,
					Default:     0,
					Description: "Verify that the commit has enough verified signatures",
				},
				FieldNameMaxCloneSizeBytes: {
					Type:        framework.TypeInt,
					Default:     10 * 1024 * 1024, // 10MB
					Description: "Max size (bytes) of in-memory clone; clone fails when exceeded (0 = no limit). Protects against OOM on large or malicious repos.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigureCreateOrUpdate,
					Summary:  "Create new gitops git_repository configuration.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigureCreateOrUpdate,
					Summary:  "Update the current gitops git_repository configuration.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigureRead,
					Summary:  "Read the current gitops git_repository configuration.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigureDelete,
					Summary:  "Delete the current gitops git_repository configuration.",
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    configureHelpSyn,
			HelpDescription: configureHelpDesc,
		},
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, fields *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, StorageKeyConfiguration)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *backend) pathConfigureCreateOrUpdate(ctx context.Context, req *logical.Request, fields *framework.FieldData) (*logical.Response, error) {
	b.Logger().Trace("Git repository configuration started")

	var config Configuration

	if req.Operation == logical.UpdateOperation {
		// For UPDATE: read existing configuration
		existingConfig, err := getConfiguration(ctx, req.Storage)
		if err != nil {
			return logical.ErrorResponse("Unable to get existing configuration: %s", err), nil
		}
		if existingConfig == nil {
			return logical.ErrorResponse("Configuration does not exist. Use CREATE operation to create it."), nil
		}
		// Start with existing configuration
		config = *existingConfig
	}

	// Update only fields that were provided in the request
	if gitRepoUrl, ok := fields.GetOk(FieldNameGitRepoUrl); ok {
		config.GitRepoUrl = gitRepoUrl.(string)
	}

	if gitBranch, ok := fields.GetOk(FieldNameGitBranch); ok {
		config.GitBranch = gitBranch.(string)
	}

	if gitCACertificate, ok := fields.GetOk(FieldNameGitCACertificate); ok {
		config.GitCACertificate = gitCACertificate.(string)
	}

	if gitPollPeriod, ok := fields.GetOk(FieldNameGitPollPeriod); ok {
		config.GitPollPeriod = time.Duration(gitPollPeriod.(int)) * time.Second
	}

	if requiredSignatures, ok := fields.GetOk(FieldNameRequiredNumberOfVerifiedSignaturesOnCommit); ok {
		config.RequiredNumberOfVerifiedSignaturesOnCommit = requiredSignatures.(int)
	}

	if maxCloneSize, ok := fields.GetOk(FieldNameMaxCloneSizeBytes); ok {
		if v, ok := maxCloneSize.(int); ok && v >= 0 {
			config.MaxCloneSizeBytes = int64(v)
		}
	}

	// Validate GitRepoUrl for CREATE operation
	if req.Operation == logical.CreateOperation && config.GitRepoUrl == "" {
		return logical.ErrorResponse("%q field value should not be empty", FieldNameGitRepoUrl), nil
	}

	// Validate GitRepoUrl if it was provided or is required
	if config.GitRepoUrl != "" {
		if _, err := transport.NewEndpoint(config.GitRepoUrl); err != nil {
			return logical.ErrorResponse("%q field is invalid: %s", FieldNameGitRepoUrl, err), nil
		}
	}

	if err := putConfiguration(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigureRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Trace("Reading git repository configuration")

	config, err := getConfiguration(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("Unable to get Configuration: %s", err), nil
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{Data: configurationStructToMap(config)}, nil
}

func (b *backend) pathConfigureDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Trace("Deleting Configuration")

	if err := deleteConfiguration(ctx, req.Storage); err != nil {
		return logical.ErrorResponse("Unable to delete Configuration: %s", err), nil
	}

	return nil, nil
}

func putConfiguration(ctx context.Context, storage logical.Storage, config Configuration) error {
	storageEntry, err := logical.StorageEntryJSON(StorageKeyConfiguration, config)
	if err != nil {
		return err
	}

	if err := storage.Put(ctx, storageEntry); err != nil {
		return err
	}

	return err
}

func getConfiguration(ctx context.Context, storage logical.Storage) (*Configuration, error) {
	storageEntry, err := storage.Get(ctx, StorageKeyConfiguration)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}

	var config *Configuration
	if err := storageEntry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func deleteConfiguration(ctx context.Context, storage logical.Storage) error {
	return storage.Delete(ctx, StorageKeyConfiguration)
}

func configurationStructToMap(config *Configuration) map[string]interface{} {
	data := structs.Map(config)
	data[FieldNameGitPollPeriod] = config.GitPollPeriod.Seconds()

	return data
}

const (
	configureHelpSyn = `
Git repository configuration of the gitops backend.
`
	configureHelpDesc = `
The gitops periodic function performs periodic run of configured command
when a new commit arrives into the configured git repository.

This is git repository configuration for the gitops plugin. Plugin will not
function when Configuration is not set.
`
)
