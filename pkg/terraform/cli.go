//go:build linux

package terraform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-git/go-billy/v6"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

const tmpfsMagic = 0x01021994

// inMemoryTempDir returns a tmpfs-backed directory suitable for os.MkdirTemp.
// It prefers /dev/shm (guaranteed tmpfs on Linux), falls back to the default
// temp directory if /tmp is already tmpfs, or returns "" as a last resort.
func inMemoryTempDir() string {
	var stat syscall.Statfs_t
	if syscall.Statfs("/dev/shm", &stat) == nil && stat.Type == tmpfsMagic {
		return "/dev/shm"
	}
	return ""
}

const (
	// StorageKeyTerraformState is the key for storing terraform state in storage
	StorageKeyTerraformState = "terraform_state"
)

// CLIConfig contains configuration for terraform CLI execution
type CLIConfig struct {
	VaultAddr      string
	VaultToken     string
	VaultNamespace string
	TfPath         string
	TfBinary       string
	TfBinarySHA256 string
	Storage        logical.Storage
	Logger         hclog.Logger
}

// ApplyTerraformFromFS extracts terraform files from the given filesystem and applies them using Terraform CLI.
//
// Directory layout inside tmpDir:
//
//	tmpDir/
//	├── workspace/   ← .tf files extracted here (CWD for terraform)
//	└── .rootfs/     ← sandbox skeleton (only in sandboxed mode)
//
// Files under config.TfPath are extracted directly into workspace/ without
// the prefix, so terraform always runs from workspace/.  The .rootfs
// sibling is derived from workDir by newSandboxedCommand and never appears
// inside /workspace after pivot_root.
func ApplyTerraformFromFS(ctx context.Context, worktreeFS billy.Filesystem, config CLIConfig) error {
	// Create temporary directory on a tmpfs-backed filesystem so that
	// sensitive .tf content never touches persistent storage.
	tmpDir, err := os.MkdirTemp(inMemoryTempDir(), "vault-plugin-terraform-*")
	if err != nil {
		return fmt.Errorf("creating temporary directory: %w", err)
	}

	workDir := filepath.Join(tmpDir, "workspace")
	statePath := filepath.Join(workDir, "terraform.tfstate")

	defer func() {
		if stateData, readErr := os.ReadFile(statePath); readErr == nil && len(stateData) > 0 {
			if saveErr := saveTerraformState(ctx, stateData, config); saveErr != nil {
				config.Logger.Warn(fmt.Sprintf("Failed to save terraform state: %v", saveErr))
			}
		}
		os.RemoveAll(tmpDir)
	}()

	config.Logger.Debug(fmt.Sprintf("Created temporary directory for terraform: %q", tmpDir))

	tfFiles, err := extractTerraformFiles(worktreeFS, workDir, config.TfPath, config.Logger)
	if err != nil {
		return fmt.Errorf("extracting terraform files: %w", err)
	}

	if len(tfFiles) == 0 {
		config.Logger.Info("No terraform files found in repository")
		return nil
	}

	if err := loadTerraformState(ctx, statePath, config); err != nil {
		return fmt.Errorf("loading terraform state: %w", err)
	}

	if err := runTerraformInit(ctx, workDir, config); err != nil {
		return fmt.Errorf("terraform init: %w", err)
	}

	if err := runTerraformPlan(ctx, workDir, config); err != nil {
		return fmt.Errorf("terraform plan: %w", err)
	}

	if err := runTerraformApply(ctx, workDir, config); err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}

	return nil
}

// extractTerraformFiles extracts files from the given filesystem to temporary directory.
func extractTerraformFiles(worktreeFS billy.Filesystem, targetDir string, tfPath string, logger hclog.Logger) ([]string, error) {
	var tfFiles []string

	normalizedTfPath := filepath.Clean(tfPath)
	if normalizedTfPath == "." {
		normalizedTfPath = ""
	}

	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := worktreeFS.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("reading directory %q: %w", dir, err)
		}
		for _, entry := range entries {
			filePath := path.Join(dir, entry.Name())
			if entry.IsDir() {
				if err := walk(filePath); err != nil {
					return err
				}
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("file info for %q: %w", filePath, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}

			normalizedFilePath := filepath.Clean(filePath)

			var targetPath string
			if normalizedTfPath != "" {
				if normalizedFilePath != normalizedTfPath && !strings.HasPrefix(normalizedFilePath, normalizedTfPath+string(filepath.Separator)) {
					continue
				}
				relPath, err := filepath.Rel(normalizedTfPath, normalizedFilePath)
				if err != nil {
					return fmt.Errorf("calculating relative path for %q: %w", filePath, err)
				}
				if strings.Contains(relPath, "..") {
					continue
				}
				targetPath = filepath.Join(targetDir, relPath)
			} else {
				if normalizedFilePath == "" || strings.Contains(normalizedFilePath, "..") || filepath.IsAbs(normalizedFilePath) {
					continue
				}
				targetPath = filepath.Join(targetDir, normalizedFilePath)
			}

			// Ensure resolved path stays under targetDir (defense in depth)
			absTarget, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("resolving target path %q: %w", targetPath, err)
			}
			absTargetDir, err := filepath.Abs(targetDir)
			if err != nil {
				return fmt.Errorf("resolving target dir: %w", err)
			}
			if !strings.HasPrefix(absTarget, absTargetDir+string(filepath.Separator)) && absTarget != absTargetDir {
				continue
			}

			if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
				return fmt.Errorf("creating directory for %q: %w", filePath, err)
			}

			srcFile, err := worktreeFS.Open(filePath)
			if err != nil {
				return fmt.Errorf("opening %q: %w", filePath, err)
			}

			dstFile, err := os.Create(targetPath)
			if err != nil {
				srcFile.Close()
				return fmt.Errorf("creating file %q: %w", targetPath, err)
			}

			_, copyErr := io.Copy(dstFile, srcFile)
			srcFile.Close()
			dstFile.Close()
			if copyErr != nil {
				return fmt.Errorf("copying file %q: %w", filePath, copyErr)
			}

			tfFiles = append(tfFiles, targetPath)
			logger.Debug(fmt.Sprintf("Extracted terraform file: %q", filePath))
		}
		return nil
	}

	if err := walk(""); err != nil {
		return nil, err
	}

	logger.Info(fmt.Sprintf("Extracted %d terraform files", len(tfFiles)))
	return tfFiles, nil
}

// setupTerraformConfigFile sets TF_CLI_CONFIG_FILE on the command.
// Uses a relative path (".terraformrc") so it works both on the host
// filesystem and inside the pivot_root'd sandbox (CWD = /workspace).
// Host TF_CLI_CONFIG_FILE takes priority when running without rootfs
// isolation; inside the sandbox it is ignored because the host path
// would not exist after pivot_root.
func setupTerraformConfigFile(workDir string, cmd *exec.Cmd) {
	if v := os.Getenv("TF_CLI_CONFIG_FILE"); v != "" {
		cmd.Env = append(cmd.Env, "TF_CLI_CONFIG_FILE="+v)
		return
	}
	terraformrcPath := filepath.Join(workDir, ".terraformrc")
	if _, err := os.Stat(terraformrcPath); err == nil {
		cmd.Env = append(cmd.Env, "TF_CLI_CONFIG_FILE=.terraformrc")
	}
}

func runTerraformInit(ctx context.Context, workDir string, config CLIConfig) error {
	tfBinary, err := getTfBinary(config)
	if err != nil {
		return err
	}
	cmd := newTerraformCommand(ctx, workDir, config, config.Logger, tfBinary, "init", "-no-color", "-input=false")
	setupTerraformConfigFile(workDir, cmd)
	cmd.Stdout = io.Discard

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	config.Logger.Info("Running terraform init")
	if err := cmd.Run(); err != nil {
		stderr := strings.TrimSpace(stderrBuf.String())
		if stderr != "" {
			return fmt.Errorf("terraform init failed: %s", stderr)
		}
		return fmt.Errorf("terraform init failed: %w", err)
	}

	config.Logger.Info("Terraform init completed successfully")
	return nil
}

func runTerraformPlan(ctx context.Context, workDir string, config CLIConfig) error {
	tfBinary, err := getTfBinary(config)
	if err != nil {
		return err
	}
	cmd := newTerraformCommand(ctx, workDir, config, config.Logger, tfBinary, "plan", "-no-color", "-input=false", "-out=tfplan")
	setupTerraformConfigFile(workDir, cmd)
	cmd.Stdout = io.Discard

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	config.Logger.Info("Running terraform plan")
	if err := cmd.Run(); err != nil {
		stderr := strings.TrimSpace(stderrBuf.String())
		if stderr != "" {
			return fmt.Errorf("terraform plan failed: %s", stderr)
		}
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	config.Logger.Info("Terraform plan completed successfully")
	return nil
}

func runTerraformApply(ctx context.Context, workDir string, config CLIConfig) error {
	tfBinary, err := getTfBinary(config)
	if err != nil {
		return err
	}
	cmd := newTerraformCommand(ctx, workDir, config, config.Logger, tfBinary, "apply", "-no-color", "-input=false", "-auto-approve", "tfplan")
	setupTerraformConfigFile(workDir, cmd)
	cmd.Stdout = io.Discard

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	config.Logger.Info("Running terraform apply")
	if err := cmd.Run(); err != nil {
		stderr := strings.TrimSpace(stderrBuf.String())
		if stderr != "" {
			return fmt.Errorf("terraform apply failed: %s", stderr)
		}
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	config.Logger.Info("Terraform apply completed successfully")
	return nil
}

func loadTerraformState(ctx context.Context, statePath string, config CLIConfig) error {
	if config.Storage == nil {
		config.Logger.Debug("Storage not provided, skipping state load")
		return nil
	}

	entry, err := config.Storage.Get(ctx, StorageKeyTerraformState)
	if err != nil {
		return fmt.Errorf("getting terraform state from storage: %w", err)
	}

	if entry == nil || len(entry.Value) == 0 {
		config.Logger.Debug("No terraform state found in storage, starting fresh")
		return nil
	}

	if err := os.WriteFile(statePath, entry.Value, 0600); err != nil {
		return fmt.Errorf("writing terraform state file: %w", err)
	}

	config.Logger.Debug("Loaded terraform state from storage")
	return nil
}

// saveTerraformState saves terraform state to storage
func saveTerraformState(ctx context.Context, state []byte, config CLIConfig) error {
	if config.Storage == nil {
		config.Logger.Debug("Storage not provided, skipping state save")
		return nil
	}

	if len(state) == 0 {
		config.Logger.Debug("No terraform state to save")
		return nil
	}

	entry := &logical.StorageEntry{
		Key:   StorageKeyTerraformState,
		Value: state,
	}

	if err := config.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("saving terraform state to storage: %w", err)
	}

	config.Logger.Info("Saved terraform state to storage")
	return nil
}

// ResolveAndValidateTfBinary resolves the terraform binary path, validates that it exists,
// is a regular file with execute permission, and optionally matches the expected SHA256.
// Empty tfBinary is treated as "terraform". Returns the absolute path to the binary or an error.
func ResolveAndValidateTfBinary(tfBinary, expectedSHA256 string) (string, error) {
	if tfBinary == "" {
		tfBinary = "terraform"
	}

	var path string
	if filepath.IsAbs(tfBinary) {
		path = tfBinary
	} else {
		var err error
		path, err = exec.LookPath(tfBinary)
		if err != nil {
			return "", fmt.Errorf("terraform binary %q not found in PATH", tfBinary)
		}
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("terraform binary not found at path %q", path)
		}
		return "", fmt.Errorf("unable to access terraform binary at %q: %w", path, err)
	}
	if fileInfo.IsDir() {
		return "", fmt.Errorf("terraform binary path %q is a directory, not a file", path)
	}
	if fileInfo.Mode()&0111 == 0 {
		return "", fmt.Errorf("terraform binary at %q does not have execute permissions", path)
	}
	if expectedSHA256 != "" {
		if err := verifyTfBinarySHA256(path, expectedSHA256); err != nil {
			return "", err
		}
	}
	return path, nil
}

// verifyTfBinarySHA256 computes SHA256 of the file at path and compares it to expectedHex (trimmed, case-insensitive).
func verifyTfBinarySHA256(path, expectedHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reading terraform binary for checksum: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20) // 1 MiB
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return fmt.Errorf("reading terraform binary for checksum: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	expected := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(expectedHex)), "0x")
	if got != expected {
		return fmt.Errorf("terraform binary SHA256 mismatch at %q: got %s, expected %s", path, got, expectedHex)
	}
	return nil
}

func getTfBinary(config CLIConfig) (string, error) {
	return ResolveAndValidateTfBinary(config.TfBinary, config.TfBinarySHA256)
}
