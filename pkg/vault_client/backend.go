package vault_client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	FieldNameVaultAddr        = "vault_addr"
	FieldNameVaultToken       = "vault_token"
	FieldNameWrappingToken    = "wrapping_token"
	FieldNameVaultNamespace   = "vault_namespace"
	FieldNameVaultTokenRotate = "rotate"
	StorageKeyConfiguration   = "vault_client_configuration"
)

type Configuration struct {
	VaultAddr        string `structs:"vault_addr" json:"vault_addr"`
	VaultToken       string `structs:"vault_token" json:"vault_token"`
	VaultNamespace   string `structs:"vault_namespace" json:"vault_namespace"`
	VaultTokenRotate bool   `structs:"rotate" json:"rotate"`
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
			Pattern: "^configure/vault/?$",
			Fields: map[string]*framework.FieldSchema{
				FieldNameVaultAddr: {
					Type:        framework.TypeString,
					Description: "Vault API address.",
				},
				FieldNameVaultToken: {
					Type:        framework.TypeString,
					Description: "Vault token for API access.",
				},
				FieldNameWrappingToken: {
					Type:        framework.TypeString,
					Description: "Wrapping vault token for API access.",
				},
				FieldNameVaultNamespace: {
					Type:        framework.TypeString,
					Description: "Vault namespace for API access.",
				},
				FieldNameVaultTokenRotate: {
					Type:        framework.TypeBool,
					Description: "Rotate vault token.",
					Default:     false,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigureCreateOrUpdate,
					Summary:  "Create new vault client configuration.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigureCreateOrUpdate,
					Summary:  "Update the current vault client configuration.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigureRead,
					Summary:  "Read the current vault client configuration.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigureDelete,
					Summary:  "Delete the current vault client configuration.",
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
	b.Logger().Trace("Vault client configuration started")

	// Get existing configuration for UPDATE operation
	var existingConfig *Configuration

	if req.Operation == logical.UpdateOperation {
		existingConfig, _ = getConfiguration(ctx, req.Storage)
	}

	config := Configuration{}

	// For UPDATE: preserve existing values if not provided in request
	// For CREATE: use provided values or empty string
	if vaultAddrVal, ok := fields.GetOk(FieldNameVaultAddr); ok {
		config.VaultAddr = strings.TrimSuffix(vaultAddrVal.(string), "/")
	} else if req.Operation == logical.UpdateOperation && existingConfig != nil {
		config.VaultAddr = existingConfig.VaultAddr
	}

	if vaultNamespaceVal, ok := fields.GetOk(FieldNameVaultNamespace); ok {
		config.VaultNamespace = vaultNamespaceVal.(string)
	} else if req.Operation == logical.UpdateOperation && existingConfig != nil {
		config.VaultNamespace = existingConfig.VaultNamespace
	}

	vaultTokenVal, vaultTokenOk := fields.GetOk(FieldNameVaultToken)
	wrappingTokenVal, wrappingTokenOk := fields.GetOk(FieldNameWrappingToken)

	if wrappingTokenOk {
		wrappingToken := wrappingTokenVal.(string)
		unwrappingToken, err := unwrapToken(ctx, &config, wrappingToken, b.Logger())
		if err != nil {
			return logical.ErrorResponse("Failed to unwrap token: %s", err), nil
		}
		config.VaultToken = unwrappingToken
	} else if vaultTokenOk {
		config.VaultToken = vaultTokenVal.(string)
	} else if req.Operation == logical.UpdateOperation && existingConfig != nil {
		config.VaultToken = existingConfig.VaultToken
	}

	// Get rotate parameter
	rotateVal, rotateOk := fields.GetOk(FieldNameVaultTokenRotate)
	rotate := rotateOk && rotateVal.(bool)

	// Variables for token rotation
	var oldToken string

	// If rotate is true and token was provided, create orphan token
	if rotate && config.VaultToken != "" {
		oldToken = config.VaultToken
		b.Logger().Debug("Token rotation requested, creating orphan token")

		newToken, err := createOrphanToken(ctx, &config, b.Logger())
		if err != nil {
			return logical.ErrorResponse("Failed to create orphan token: %s", err), nil
		}

		// Use the new orphan token
		config.VaultToken = newToken
		b.Logger().Debug("Orphan token created successfully")
	}

	// Save configuration
	if err := putConfiguration(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	// Revoke the old token only after successful save
	if rotate && oldToken != "" {
		b.Logger().Debug("New token saved successfully, revoking old token")
		if err := revokeTokenSelf(ctx, &config, oldToken, b.Logger()); err != nil {
			// Log warning but don't fail - the new token is already saved
			b.Logger().Warn(fmt.Sprintf("Failed to revoke old token: %s", err))
		} else {
			b.Logger().Debug("Token rotation completed successfully")
		}
	}

	return nil, nil
}

func (b *backend) pathConfigureRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Trace("Reading vault client configuration")

	config, err := GetConfig(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("Unable to get Configuration: %s", err), nil
	}
	if config == nil {
		return nil, nil
	}

	// Return only vault_addr, not vault_token
	data := map[string]interface{}{
		FieldNameVaultAddr: config.VaultAddr,
	}

	return &logical.Response{Data: data}, nil
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

	return nil
}

func getConfiguration(ctx context.Context, storage logical.Storage) (*Configuration, error) {
	storageEntry, err := storage.Get(ctx, StorageKeyConfiguration)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		return nil, nil
	}

	var config Configuration
	if err := storageEntry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func deleteConfiguration(ctx context.Context, storage logical.Storage) error {
	return storage.Delete(ctx, StorageKeyConfiguration)
}

// GetConfig returns the configuration for use in other packages
func GetConfig(ctx context.Context, storage logical.Storage) (*Configuration, error) {
	config, err := getConfiguration(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("unable to get Configuration: %w", err)
	}
	if config == nil {
		config = &Configuration{VaultAddr: "", VaultToken: "", VaultNamespace: ""}
	}
	return config, nil
}

// NewClientFromConfig builds a Vault api.Client from plugin configuration.
func NewClientFromConfig(config *Configuration) (*api.Client, error) {
	cfg := api.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("reading vault env: %w", err)
	}
	if config.VaultAddr != "" {
		cfg.Address = config.VaultAddr
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	client.SetToken(config.VaultToken)
	if config.VaultNamespace != "" {
		client.SetNamespace(config.VaultNamespace)
	}
	return client, nil
}

// TokenTTL represents token TTL information
type TokenTTL struct {
	TTL        time.Duration
	ExpireTime time.Time
}

// LookupTokenSelf performs /auth/token/lookup-self API call and returns TTL
func LookupTokenSelf(ctx context.Context, config *Configuration, logger hclog.Logger) (*TokenTTL, error) {
	client, err := NewClientFromConfig(config)
	if err != nil {
		return nil, err
	}

	secret, err := client.Auth().Token().RenewSelf(0)
	if err != nil {
		return nil, fmt.Errorf("renewing token: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, errors.New("renew token response is empty")
	}

	ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
	expireTime := time.Now().Add(ttl)

	logger.Info(fmt.Sprintf("Token TTL: %v, Expire time: %v", ttl, expireTime))

	return &TokenTTL{
		TTL:        ttl,
		ExpireTime: expireTime,
	}, nil
}

// RenewTokenSelf performs /auth/token/renew-self API call and returns new TTL
func RenewTokenSelf(ctx context.Context, config *Configuration, logger hclog.Logger) (*TokenTTL, error) {
	client, err := NewClientFromConfig(config)
	if err != nil {
		return nil, err
	}

	secret, err := client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("renewing token: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, errors.New("renew token response is empty")
	}

	ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
	expireTime := time.Now().Add(ttl)

	logger.Info(fmt.Sprintf("Token renewed, new TTL: %v, Expire time: %v", ttl, expireTime))

	return &TokenTTL{
		TTL:        ttl,
		ExpireTime: expireTime,
	}, nil
}

// unwrapToken unwraps a wrapped token and returns the actual token
func unwrapToken(ctx context.Context, config *Configuration, wrappingToken string, logger hclog.Logger) (string, error) {
	client, err := NewClientFromConfig(config)
	if err != nil {
		return "", err
	}

	secret, err := client.Logical().UnwrapWithContext(ctx, wrappingToken)
	if err != nil {
		return "", fmt.Errorf("unwrap: %w", err)
	}
	if secret == nil {
		return "", errors.New("unwrap response is empty")
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", errors.New("unwrapped secret does not contain a token")
	}

	logger.Debug("Wrapped token unwrapped successfully")
	return secret.Auth.ClientToken, nil
}

// createOrphanToken creates a new orphan token using the provided token and returns the new token
// The new token will have the same parameters (policies, period, ttl, etc.) as the old token
func createOrphanToken(ctx context.Context, config *Configuration, logger hclog.Logger) (string, error) {
	client, err := NewClientFromConfig(config)
	if err != nil {
		return "", err
	}

	// Lookup current token to get its parameters
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("looking up token: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", errors.New("token lookup response is empty")
	}

	// Extract token parameters from lookup response
	tokenCreateReq := &api.TokenCreateRequest{}

	// Extract policies
	if policiesRaw, ok := secret.Data["policies"].([]interface{}); ok {
		policies := make([]string, 0, len(policiesRaw))
		for _, p := range policiesRaw {
			if policy, ok := p.(string); ok {
				policies = append(policies, policy)
			}
		}
		tokenCreateReq.Policies = policies
	}

	// Extract period (if set) - convert to string format
	var periodStr string
	if periodRaw, ok := secret.Data["period"]; ok && periodRaw != nil {
		if periodStrVal, ok := periodRaw.(string); ok {
			periodStr = periodStrVal
		} else if period, ok := periodRaw.(json.Number); ok {
			if periodInt, err := period.Int64(); err == nil {
				periodDuration := time.Duration(periodInt) * time.Second
				periodStr = periodDuration.String()
			}
		}
		if periodStr != "" {
			tokenCreateReq.Period = periodStr
		}
	}

	// Extract TTL (if period is not set) - convert to string format
	if periodStr == "" {
		if ttlRaw, ok := secret.Data["ttl"]; ok && ttlRaw != nil {
			var ttlStr string
			if ttlStrVal, ok := ttlRaw.(string); ok {
				ttlStr = ttlStrVal
			} else if ttlNum, ok := ttlRaw.(json.Number); ok {
				if ttlInt, err := ttlNum.Int64(); err == nil {
					ttlDuration := time.Duration(ttlInt) * time.Second
					ttlStr = ttlDuration.String()
				}
			}
			if ttlStr != "" {
				tokenCreateReq.TTL = ttlStr
			}
		}
	}

	// Extract display name
	if displayName, ok := secret.Data["display_name"].(string); ok {
		tokenCreateReq.DisplayName = displayName
	}

	// Extract num_uses
	if numUsesRaw, ok := secret.Data["num_uses"]; ok {
		if numUses, ok := numUsesRaw.(json.Number); ok {
			if numUsesInt, err := numUses.Int64(); err == nil {
				tokenCreateReq.NumUses = int(numUsesInt)
			}
		}
	}

	// Extract renewable
	if renewable, ok := secret.Data["renewable"].(bool); ok {
		tokenCreateReq.Renewable = &renewable
	}

	// Extract explicit_max_ttl - convert to string format
	if explicitMaxTTLRaw, ok := secret.Data["explicit_max_ttl"]; ok && explicitMaxTTLRaw != nil {
		var explicitMaxTTLStr string
		if explicitMaxTTLStrVal, ok := explicitMaxTTLRaw.(string); ok {
			explicitMaxTTLStr = explicitMaxTTLStrVal
		} else if explicitMaxTTLNum, ok := explicitMaxTTLRaw.(json.Number); ok {
			if explicitMaxTTLInt, err := explicitMaxTTLNum.Int64(); err == nil {
				explicitMaxTTLDuration := time.Duration(explicitMaxTTLInt) * time.Second
				explicitMaxTTLStr = explicitMaxTTLDuration.String()
			}
		}
		if explicitMaxTTLStr != "" {
			tokenCreateReq.ExplicitMaxTTL = explicitMaxTTLStr
		}
	}

	// Extract metadata
	if metadataRaw, ok := secret.Data["meta"].(map[string]interface{}); ok {
		metadata := make(map[string]string)
		for k, v := range metadataRaw {
			if val, ok := v.(string); ok {
				metadata[k] = val
			}
		}
		if len(metadata) > 0 {
			tokenCreateReq.Metadata = metadata
		}
	}

	// Create orphan token with cloned parameters
	createSecret, err := client.Auth().Token().CreateOrphanWithContext(ctx, tokenCreateReq)
	if err != nil {
		return "", fmt.Errorf("creating orphan token: %w", err)
	}
	if createSecret == nil || createSecret.Auth == nil || createSecret.Auth.ClientToken == "" {
		return "", errors.New("orphan token creation response is empty or invalid")
	}

	newToken := createSecret.Auth.ClientToken
	logger.Debug("Orphan token created successfully with cloned parameters")

	return newToken, nil
}

// revokeTokenSelf revokes the given token using revoke-self endpoint
func revokeTokenSelf(ctx context.Context, config *Configuration, tokenToRevoke string, logger hclog.Logger) error {
	cfg := *config
	cfg.VaultToken = tokenToRevoke
	client, err := NewClientFromConfig(&cfg)
	if err != nil {
		return err
	}

	// Revoke the token
	if err := client.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
		return fmt.Errorf("revoking token: %w", err)
	}

	logger.Debug("Token revoked successfully")
	return nil
}

const (
	configureHelpSyn = `
Vault client configuration of the gitops backend.
`
	configureHelpDesc = `
The vault client configuration is used to connect to Vault API for applying policies.

This is vault client configuration for the gitops plugin.
`
)
