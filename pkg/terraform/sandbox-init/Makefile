BIN_DIR  := bin
SRC      := main.c
CFLAGS   := -static -Os -s -Wall -Wextra -Werror
TARGETS  := $(BIN_DIR)/sandbox-init-amd64 $(BIN_DIR)/sandbox-init-arm64

# Cross-compilers: override via env if using a different toolchain.
CC_AMD64 ?= x86_64-linux-musl-gcc
CC_ARM64 ?= aarch64-linux-musl-gcc

.PHONY: all clean docker

all: $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/sandbox-init-amd64: $(SRC) | $(BIN_DIR)
	$(CC_AMD64) $(CFLAGS) -o $@ $<

$(BIN_DIR)/sandbox-init-arm64: $(SRC) | $(BIN_DIR)
	$(CC_ARM64) $(CFLAGS) -o $@ $<

# Build both architectures inside a Docker container (works on any host OS).
docker:
	docker run --rm -v "$(CURDIR):/src" -w /src alpine:latest sh -c '\
		apk add --no-cache gcc musl-dev make && \
		make CC_AMD64=gcc CC_ARM64=gcc clean all'

# Alternative: build using zig cc as cross-compiler (works on macOS/Linux).
zig:
	make CC_AMD64="zig cc -target x86_64-linux-musl" \
	     CC_ARM64="zig cc -target aarch64-linux-musl" \
	     all

clean:
	rm -rf $(BIN_DIR)
