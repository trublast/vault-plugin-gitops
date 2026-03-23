//go:build linux && arm64

package terraform

import _ "embed"

//go:embed sandbox-init/bin/sandbox-init-arm64
var sandboxInitBinary []byte
