package sodium

import "fmt"
import "unsafe"

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"

//MemZero sets the buffer to zero
func MemZero(buff1 Bytes) {
	if len(buff1) > 0 {
		C.sodium_memzero(unsafe.Pointer(&buff1[0]), C.size_t(len(buff1)))
	}
}

//MemCmp compare to buffer without leaking timing infomation
func MemCmp(buff1, buff2 Bytes, length int) int {
	if length > len(buff1) || length > len(buff2) {
		panic(fmt.Sprintf("Attempt to compare more bytes (%d) than provided "+
			"(%d, %d)", length, len(buff1), len(buff2)))
	}
	return int(C.sodium_memcmp(unsafe.Pointer(&buff1[0]),
		unsafe.Pointer(&buff2[0]),
		C.size_t(length)))
}
