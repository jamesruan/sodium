package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoShortHashBytes() int {
	return int(C.crypto_shorthash_bytes())
}

func CryptoShortHashKeyBytes() int {
	return int(C.crypto_shorthash_keybytes())
}

func CryptoShortHash(in []byte, key []byte) (out []byte) {
	CheckSize(key, CryptoShortHashKeyBytes(), "key")
	out = make([]byte, CryptoShortHashBytes())
	if int(C.crypto_shorthash(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0]))) != 0 {
		panic("see libsodium")
	}

	return
}
