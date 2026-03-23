//go:build linux

package terraform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hashicorp/go-hclog"
)

// sandboxSupported lazily probes whether unprivileged user namespaces
// are usable on this kernel (kernel.unprivileged_userns_clone=1).
var sandboxSupported = sync.OnceValue(func() bool {
	cmd := exec.Command("/proc/self/exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	cmd.Process.Kill()
	cmd.Wait()
	return true
})

// apparmorRestrictsUserns reports whether AppArmor blocks mount/pivot_root
// inside unprivileged user namespaces (Ubuntu 23.10+).
func apparmorRestrictsUserns() bool {
	data, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if err != nil {
		return false
	}
	return len(data) > 0 && data[0] == '1'
}

// writeSandboxInit writes the embedded sandbox-init binary to path
// (unless it already exists).  The caller is responsible for cleanup.
func writeSandboxInit(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, sandboxInitBinary, 0700)
}

// newTerraformCommand creates an exec.Cmd for the given terraform binary
// running inside a full sandbox (user/mount/PID/UTS namespaces + pivot_root).
//
// The embedded sandbox-init helper is written into the tmpfs-backed tmpDir
// (next to workspace/) and used as the entry point.  The helper receives
// SANDBOX_ROOTFS and prepares a minimal rootfs with only the files terraform
// needs, then pivot_root's into it and execve's terraform.
//
// Network is intentionally shared: terraform needs connectivity to
// download providers (init) and to reach the Vault API (plan/apply).
//
// Returns an error if the sandbox cannot be set up (unsupported kernel,
// AppArmor restrictions, filesystem errors).
func newTerraformCommand(ctx context.Context, workDir string, config CLIConfig, logger hclog.Logger, tfBinary string, args ...string) (*exec.Cmd, error) {
	if !sandboxSupported() {
		return nil, fmt.Errorf("sandbox: unprivileged user namespaces not available " +
			"(sysctl kernel.unprivileged_userns_clone=1 required)")
	}
	if apparmorRestrictsUserns() {
		return nil, fmt.Errorf("sandbox: AppArmor blocks mount/pivot_root in unprivileged user namespaces " +
			"(kernel.apparmor_restrict_unprivileged_userns=1); " +
			"run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 " +
			"or create an AppArmor profile with 'userns' permission")
	}

	tmpDir := filepath.Dir(workDir)
	rootfsDir := filepath.Join(tmpDir, ".rootfs")

	initPath := filepath.Join(tmpDir, "sandbox-init")
	if err := writeSandboxInit(initPath); err != nil {
		return nil, fmt.Errorf("sandbox: writing sandbox-init: %w", err)
	}
	if err := os.MkdirAll(rootfsDir, 0700); err != nil {
		return nil, fmt.Errorf("sandbox: creating rootfs dir: %w", err)
	}

	cmdArgs := append([]string{tfBinary}, args...)
	cmd := exec.CommandContext(ctx, initPath, cmdArgs...)
	cmd.Dir = workDir
	cmd.Env = append(
		buildSandboxEnv(config),
		"SANDBOX_ROOTFS="+rootfsDir,
	)

	uid := os.Getuid()
	gid := os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		Pdeathsig: syscall.SIGKILL,
	}

	logger.Debug("Using sandbox-init with rootfs isolation",
		"initPath", initPath, "rootfs", rootfsDir)
	return cmd, nil
}

// buildSandboxEnv constructs a minimal allow-list of environment variables
// for the sandboxed terraform process.  Paths are adjusted for the
// pivot_root'd rootfs where the workspace is at /workspace.
func buildSandboxEnv(config CLIConfig) []string {
	env := []string{
		"HOME=/workspace",
		"TMPDIR=/tmp",
		"PATH=/usr/bin",
		"TF_IN_AUTOMATION=true",
		"TF_INPUT=false",
		"CHECKPOINT_DISABLE=true",
	}

	if config.VaultAddr != "" {
		env = append(env, "VAULT_ADDR="+config.VaultAddr)
	}
	if config.VaultToken != "" {
		env = append(env, "VAULT_TOKEN="+config.VaultToken)
	}
	if config.VaultNamespace != "" {
		env = append(env, "VAULT_NAMESPACE="+config.VaultNamespace)
	}

	return env
}
