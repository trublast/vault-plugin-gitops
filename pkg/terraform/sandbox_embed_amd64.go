//go:build linux && amd64 && sandbox_init

package terraform

import _ "embed"

//go:embed sandbox-init/bin/sandbox-init-amd64
var sandboxInitBinary []byte
