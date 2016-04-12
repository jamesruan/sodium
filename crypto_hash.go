package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoHashBytes() int {
	return int(C.crypto_hash_bytes())
}

func CryptoHashPrimitive() string {
	return C.GoString(C.crypto_hash_primitive())
}

func CryptoHash(in []byte) (out []byte) {
	out = make([]byte, CryptoHashBytes())
	if int(C.crypto_hash(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(len(in)))) != 0 {
		panic("see libsodium")
	}

	return
}
