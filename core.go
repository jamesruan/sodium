package sodium

import "fmt"

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func init() {
	result := int(C.sodium_init())
	if result != 0 {
		panic(fmt.Sprintf("Sodium initialization failed, result code %d.",
			result))
	}
}
