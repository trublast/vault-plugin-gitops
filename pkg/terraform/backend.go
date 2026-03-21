//go:build linux

package terraform

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	FieldNameTfPath         = "terraform_path"
	FieldNameTfBinary       = "terraform_binary"
	FieldNameTfBinarySHA256 = "terraform_binary_sha256"

	StorageKeyConfiguration = "terraform_configuration"
)

type Configuration struct {
	TfPath         string `structs:"terraform_path" json:"terraform_path,omitempty"`
	TfBinary       string `structs:"terraform_binary" json:"terraform_binary,omitempty"`
	TfBinarySHA256 string `structs:"terraform_binary_sha256" json:"terraform_binary_sha256,omitempty"`
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
			Pattern: "^configure/terraform/?$",
			Fields: map[string]*framework.FieldSchema{
				FieldNameTfPath: {
					Type:        framework.TypeString,
					Default:     "",
					Description: "Path to Terraform files. Default is root of the repository.",
					Required:    false,
				},
				FieldNameTfBinary: {
					Type:        framework.TypeString,
					Default:     "terraform",
					Description: "Full path to Terraform binary. Default is terraform.",
					Required:    false,
				},
				FieldNameTfBinarySHA256: {
					Type:        framework.TypeString,
					Description: "Optional SHA256 checksum of the Terraform binary. If set, the binary is verified against this checksum at configuration time and before each run.",
					Required:    false,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigureCreateOrUpdate,
					Summary:  "Create new terraform configuration.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigureCreateOrUpdate,
					Summary:  "Update the current terraform configuration.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigureRead,
					Summary:  "Read the current terraform configuration.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigureDelete,
					Summary:  "Delete the current terraform configuration.",
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
	b.Logger().Trace("Terraform configuration started")

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
	if tfPath, ok := fields.GetOk(FieldNameTfPath); ok {
		config.TfPath = tfPath.(string)
	}

	// Validate TfPath if it was provided
	if config.TfPath != "" {
		if filepath.Clean(config.TfPath) != config.TfPath || strings.Contains(config.TfPath, "..") {
			return logical.ErrorResponse("%q field is invalid", FieldNameTfPath), nil
		}
	}

	if tfBinary, ok := fields.GetOk(FieldNameTfBinary); ok {
		config.TfBinary = tfBinary.(string)
	}

	if tfBinarySHA256, ok := fields.GetOk(FieldNameTfBinarySHA256); ok {
		config.TfBinarySHA256 = strings.TrimSpace(tfBinarySHA256.(string))
	}

	// Validate TfBinary if it was provided or set
	if config.TfBinary != "" {
		if _, err := ResolveAndValidateTfBinary(config.TfBinary, config.TfBinarySHA256); err != nil {
			return logical.ErrorResponse("%q field is invalid: %s", FieldNameTfBinary, err), nil
		}
	}

	if err := putConfiguration(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigureRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Trace("Reading terraform configuration")

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
	return structs.Map(config)
}

// GetConfig returns the configuration for use in other packages
func GetConfig(ctx context.Context, storage logical.Storage) (*Configuration, error) {
	config, err := getConfiguration(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get Configuration: %w", err)
	}
	if config == nil {
		config = &Configuration{TfPath: ""}
	}
	return config, nil
}

const (
	configureHelpSyn = `
Terraform configuration of the gitops backend.
`
	configureHelpDesc = `
The terraform configuration is used to specify the path to Terraform files within the git repository.

This is terraform configuration for the gitops plugin.
`
)
