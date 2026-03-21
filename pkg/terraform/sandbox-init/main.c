/*
 * sandbox-init — rootfs isolation helper for vault-plugin-gitops.
 *
 * Executed as the first process inside Linux user/mount/PID/UTS namespaces
 * (created by the Go plugin via SysProcAttr.Cloneflags).  Prepares a
 * minimal rootfs with only the files terraform needs, then pivot_root's
 * into it and execve's the terraform binary.
 *
 * After pivot_root the terraform process sees:
 *   /workspace/         ← .tf files and state (read-write)
 *   /usr/bin/terraform  ← the binary (read-only)
 *   /etc/ssl/           ← CA certificates (read-only)
 *   /etc/resolv.conf    ← DNS resolver (read-only)
 *   /proc               ← fresh procfs for PID namespace
 *   /tmp                ← tmpfs scratch space
 *   /dev/{null,zero,urandom}
 *
 * Everything else from the host filesystem is inaccessible.
 *
 * Interface (set by Go plugin):
 *   SANDBOX_ROOTFS  env  – writable directory to use as new root
 *   argv[1]              – terraform binary (host path)
 *   argv[2:]             – terraform arguments
 *   CWD                  – terraform workspace with .tf files (host path)
 *
 * Build (static, no runtime deps, works in distroless):
 *   musl-gcc -static -Os -s -o sandbox-init main.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TF_BIN_INNER  "/usr/bin/terraform"
#define WORKSPACE     "/workspace"

extern char **environ;

static void mkdirp(const char *path) {
	char buf[4096];
	snprintf(buf, sizeof(buf), "%s", path);
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(buf, 0755);
			*p = '/';
		}
	}
	mkdir(buf, 0755);
}

static void touch(const char *path) {
	int fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) close(fd);
}

static void bind_mount(const char *src, const char *dst, int readonly) {
	if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
		dprintf(STDERR_FILENO, "sandbox: bind %s -> %s: %s\n",
			src, dst, strerror(errno));
		return;
	}
	if (readonly)
		mount(NULL, dst, NULL,
		      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID, NULL);
}

static void bind_if_exists(const char *host_path, const char *root,
			    const char *inner, int is_dir, int readonly) {
	if (access(host_path, F_OK) != 0) return;
	char dst[4096];
	snprintf(dst, sizeof(dst), "%s%s", root, inner);
	if (is_dir)
		mkdirp(dst);
	else
		touch(dst);
	bind_mount(host_path, dst, readonly);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		dprintf(STDERR_FILENO,
			"sandbox-init: usage: sandbox-init <binary> [args...]\n");
		return 1;
	}

	const char *rootfs = getenv("SANDBOX_ROOTFS");
	if (!rootfs || !*rootfs) {
		dprintf(STDERR_FILENO, "sandbox-init: SANDBOX_ROOTFS not set\n");
		return 1;
	}

	char cwd[4096];
	if (!getcwd(cwd, sizeof(cwd))) {
		dprintf(STDERR_FILENO, "sandbox-init: getcwd: %s\n",
			strerror(errno));
		return 1;
	}

	const char *tf_host = argv[1];

	/* ---- make host mount tree private ---- */
	mount("", "/", NULL, MS_PRIVATE | MS_REC, NULL);

	/* ---- create rootfs skeleton ---- */
	char buf[4096];

	#define MK(sub) do { \
		snprintf(buf, sizeof(buf), "%s" sub, rootfs); mkdirp(buf); \
	} while (0)

	MK("/usr/bin");
	MK("/etc/ssl");
	MK("/proc");
	MK("/tmp");
	MK("/dev");
	MK(WORKSPACE);
	MK("/.pivot");

	/* ---- workspace: read-write (contains .tf files, state, providers) ---- */
	snprintf(buf, sizeof(buf), "%s" WORKSPACE, rootfs);
	bind_mount(cwd, buf, /*readonly=*/0);

	/* ---- terraform binary: read-only ---- */
	snprintf(buf, sizeof(buf), "%s" TF_BIN_INNER, rootfs);
	touch(buf);
	bind_mount(tf_host, buf, /*readonly=*/1);

	/* ---- TLS certificates ---- */
	bind_if_exists("/etc/ssl",  rootfs, "/etc/ssl",  1, 1);
	bind_if_exists("/etc/pki",  rootfs, "/etc/pki",  1, 1);

	/* ---- DNS ---- */
	bind_if_exists("/etc/resolv.conf", rootfs, "/etc/resolv.conf", 0, 1);
	bind_if_exists("/etc/hosts",       rootfs, "/etc/hosts",       0, 1);

	/* ---- /dev: tmpfs + essential devices from host ---- */
	snprintf(buf, sizeof(buf), "%s/dev", rootfs);
	mount("tmpfs", buf, "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV,
	      "size=64k,mode=755");
	bind_if_exists("/dev/null",    rootfs, "/dev/null",    0, 0);
	bind_if_exists("/dev/zero",    rootfs, "/dev/zero",    0, 0);
	bind_if_exists("/dev/urandom", rootfs, "/dev/urandom", 0, 0);

	/* ---- /proc: fresh mount for PID namespace ---- */
	snprintf(buf, sizeof(buf), "%s/proc", rootfs);
	mount("proc", buf, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

	/* ---- /tmp: tmpfs scratch ---- */
	snprintf(buf, sizeof(buf), "%s/tmp", rootfs);
	mount("tmpfs", buf, "tmpfs", MS_NOSUID | MS_NODEV, "size=64m,mode=1777");

	/* ---- pivot_root ---- */
	mount(rootfs, rootfs, NULL, MS_BIND, NULL);

	snprintf(buf, sizeof(buf), "%s/.pivot", rootfs);
	if (syscall(SYS_pivot_root, rootfs, buf) != 0) {
		dprintf(STDERR_FILENO, "sandbox-init: pivot_root: %s\n",
			strerror(errno));
		return 1;
	}

	/* detach old root and remove mount point */
	umount2("/.pivot", MNT_DETACH);
	rmdir("/.pivot");

	if (chdir(WORKSPACE) != 0) {
		dprintf(STDERR_FILENO, "sandbox-init: chdir " WORKSPACE ": %s\n",
			strerror(errno));
		return 1;
	}

	/* ---- prepare argv for terraform ---- */
	int nargs = argc; /* argc includes argv[0]=sandbox-init */
	char **new_argv = calloc(nargs, sizeof(char *));
	if (!new_argv) return 1;

	new_argv[0] = TF_BIN_INNER;
	for (int i = 2; i < argc; i++)
		new_argv[i - 1] = argv[i];

	unsetenv("SANDBOX_ROOTFS");

	execve(TF_BIN_INNER, new_argv, environ);

	dprintf(STDERR_FILENO, "sandbox-init: exec " TF_BIN_INNER ": %s\n",
		strerror(errno));
	return 1;
}
