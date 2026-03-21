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
	"golang.org/x/sys/unix"
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

// sandboxInitFD creates a memfd containing the embedded sandbox-init
// binary and returns a /proc/self/fd/N path that can be exec'd.
// The fd is kept open for the lifetime of the process.
var sandboxInitFD = sync.OnceValues(func() (string, error) {
	if len(sandboxInitBinary) == 0 {
		return "", fmt.Errorf("sandbox-init binary not embedded (build with -tags sandbox_init)")
	}

	fd, err := unix.MemfdCreate("sandbox-init", 0)
	if err != nil {
		return "", fmt.Errorf("memfd_create: %w", err)
	}

	if _, err := syscall.Write(fd, sandboxInitBinary); err != nil {
		syscall.Close(fd)
		return "", fmt.Errorf("writing sandbox-init to memfd: %w", err)
	}

	return fmt.Sprintf("/proc/self/fd/%d", fd), nil
})

// newTerraformCommand creates an exec.Cmd for the given terraform binary.
// When the kernel supports unprivileged user namespaces the process runs
// inside user/mount/PID/UTS namespaces; otherwise it falls back to an
// unsandboxed execution with a warning.
func newTerraformCommand(ctx context.Context, workDir string, config CLIConfig, logger hclog.Logger, tfBinary string, args ...string) *exec.Cmd {
	if sandboxSupported() {
		logger.Debug("Creating sandboxed terraform command", "binary", tfBinary, "args", args)
		return newSandboxedCommand(ctx, workDir, config, logger, tfBinary, args...)
	}
	logger.Warn("Linux user namespaces not available (kernel.unprivileged_userns_clone=0?), running terraform WITHOUT sandbox isolation")
	return newUnsandboxedCommand(ctx, workDir, config, tfBinary, args...)
}

// newSandboxedCommand creates an exec.Cmd inside Linux namespaces.
//
// When the embedded sandbox-init helper is available (built with
// -tags sandbox_init), it is loaded into memory via memfd_create and
// used as the entry point.  The helper receives SANDBOX_ROOTFS pointing
// to a directory it will use as the new root after pivot_root.  Inside
// the rootfs only the workspace (.tf files), the terraform binary,
// TLS certificates, DNS config and essential /dev nodes are visible.
//
// Without the helper the terraform binary is executed directly; mount
// namespace isolation is nominal but PID/UTS/user namespaces still
// apply.
//
// Network is intentionally shared: terraform needs connectivity to
// download providers (init) and to reach the Vault API (plan/apply).
func newSandboxedCommand(ctx context.Context, workDir string, config CLIConfig, logger hclog.Logger, tfBinary string, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	sandboxed := false

	if initPath, err := sandboxInitFD(); err == nil {
		rootfsDir := filepath.Join(workDir, ".rootfs")
		if mkErr := os.MkdirAll(rootfsDir, 0700); mkErr != nil {
			logger.Warn("Failed to create rootfs dir, falling back", "error", mkErr)
		} else {
			cmdArgs := append([]string{tfBinary}, args...)
			cmd = exec.CommandContext(ctx, initPath, cmdArgs...)
			sandboxed = true
			logger.Debug("Using sandbox-init with rootfs isolation via memfd",
				"rootfs", rootfsDir)
		}
	} else if len(sandboxInitBinary) > 0 {
		logger.Warn("Failed to prepare sandbox-init helper, falling back to namespace-only", "error", err)
	}

	if cmd == nil {
		cmd = exec.CommandContext(ctx, tfBinary, args...)
	}

	cmd.Dir = workDir
	env := buildCleanEnv(config, workDir, sandboxed)
	if sandboxed {
		rootfsDir := filepath.Join(workDir, ".rootfs")
		env = append(env, "SANDBOX_ROOTFS="+rootfsDir)
	}
	cmd.Env = env

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
	return cmd
}

// newUnsandboxedCommand creates a plain exec.Cmd with a clean environment
// but without namespace isolation.
func newUnsandboxedCommand(ctx context.Context, workDir string, config CLIConfig, tfBinary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, tfBinary, args...)
	cmd.Dir = workDir
	cmd.Env = buildCleanEnv(config, workDir, false)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
	return cmd
}

// buildCleanEnv constructs a minimal allow-list of environment variables.
// When sandboxed is true, paths are adjusted for the pivot_root'd rootfs
// where the workspace is at /workspace and /tmp is a separate tmpfs.
func buildCleanEnv(config CLIConfig, workDir string, sandboxed bool) []string {
	home := workDir
	tmpdir := workDir
	pathEnv := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	if sandboxed {
		home = "/workspace"
		tmpdir = "/tmp"
		pathEnv = "/usr/bin"
	}

	env := []string{
		"HOME=" + home,
		"TMPDIR=" + tmpdir,
		"PATH=" + pathEnv,
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

	// TLS CA bundle paths: propagated from host only when NOT sandboxed
	// (inside the rootfs /etc/ssl is bind-mounted from the host).
	if !sandboxed {
		for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"} {
			if v := os.Getenv(key); v != "" {
				env = append(env, key+"="+v)
			}
		}
	}

	return env
}
