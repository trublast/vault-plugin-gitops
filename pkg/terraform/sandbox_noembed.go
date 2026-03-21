//go:build linux && !sandbox_init

package terraform

// sandboxInitBinary is nil when built without the sandbox_init tag.
// The sandbox falls back to namespace-only isolation (no mount setup).
var sandboxInitBinary []byte
