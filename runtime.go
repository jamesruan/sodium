package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	RuntimeHasNeon = bool(C.sodium_runtime_has_neon() != 0)
	RuntimeHasSse2 = bool(C.sodium_runtime_has_sse2() != 0)
	RuntimeHasSse3 = bool(C.sodium_runtime_has_sse3() != 0)
)
