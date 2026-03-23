BINARY_NAME := gitops
TOOL_BINARY  := gitops-tool
VAULT_BINARY := vault
# Version for -X ldflag (empty if not in git / no tag)
VERSION      := $(shell git describe --tags --always --dirty=-dev 2>/dev/null || true)
LDFLAGS      := -s -w

PLUGIN_LDFLAGS := $(LDFLAGS) -X github.com/trublast/vault-plugin-gitops.projectVersion=$(VERSION)

.PHONY: all build build-tool clean test e2e build-sandbox-init

all: build build-tool

# Build the plugin (requires: make build-sandbox-init first).
build:
	GOOS=linux go build -ldflags '$(PLUGIN_LDFLAGS)' -o $(BINARY_NAME) ./cmd/plugin-gitops

build-gitops-only:
	go build -tags no_terraform -ldflags '$(PLUGIN_LDFLAGS)' -o $(BINARY_NAME) ./cmd/plugin-gitops

build-terraform-only:
	GOOS=linux go build -tags no_gitops -ldflags '$(PLUGIN_LDFLAGS)' -o $(BINARY_NAME) ./cmd/plugin-gitops

# Compile the C sandbox-init helper for amd64 and arm64 (static musl).
# Requires musl cross-compilers or use: make build-sandbox-init-docker
build-sandbox-init:
	$(MAKE) -C pkg/terraform/sandbox-init all

build-sandbox-init-docker:
	$(MAKE) -C pkg/terraform/sandbox-init docker

build-tool:
	go build -ldflags '$(LDFLAGS) -X main.projectVersion=$(VERSION)' -o $(TOOL_BINARY) ./cmd/tool

clean:
	rm -f $(BINARY_NAME) $(TOOL_BINARY)

test:
	go test ./...

e2e: build-tool
	$(VAULT_BINARY) server -dev -dev-root-token-id=root & \
	VAULT_PID=$$!; \
	sleep 3; \
	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ./$(TOOL_BINARY) test examples/full; EXIT=$$?; \
	kill $$VAULT_PID 2>/dev/null || true; \
	exit $$EXIT
