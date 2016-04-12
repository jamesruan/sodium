package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoGenericHashBytesMin() int {
	return int(C.crypto_generichash_bytes_min())
}

func CryptoGenericHashBytesMax() int {
	return int(C.crypto_generichash_bytes_max())
}

func CryptoGenericHashBytes() int {
	return int(C.crypto_generichash_bytes())
}

func CryptoGenericHashKeyBytesMin() int {
	return int(C.crypto_generichash_keybytes_min())
}

func CryptoGenericHashKeyBytesMax() int {
	return int(C.crypto_generichash_keybytes_max())
}

func CryptoGenericHashKeyBytes() int {
	return int(C.crypto_generichash_keybytes())
}

func CryptoGenericHashPrimitive() string {
	return C.GoString(C.crypto_generichash_primitive())
}

func CryptoGenericHashStateBytes() int {
	return int(C.crypto_generichash_statebytes())
}

func CryptoGenericHash(outlen int, in []byte, key []byte) (out []byte) {
	CheckSizeInRange(outlen, CryptoGenericHashBytesMin(), CryptoGenericHashBytesMax(), "out")
	CheckSizeInRange(len(key), CryptoGenericHashKeyBytesMin(), CryptoGenericHashKeyBytesMax(), "key")
	out = make([]byte, outlen)
	if int(C.crypto_generichash(
		(*C.uchar)(&out[0]),
		(C.size_t)(outlen),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0]),
		(C.size_t)(len(key)))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoGenericHashInit(key []byte, outlen int) (state *C.struct_crypto_generichash_blake2b_state) {
	CheckSizeInRange(outlen, CryptoGenericHashBytesMin(), CryptoGenericHashBytesMax(), "out")
	state = new(C.struct_crypto_generichash_blake2b_state)
	if int(C.crypto_generichash_init(
		(*C.struct_crypto_generichash_blake2b_state)(state),
		(*C.uchar)(&key[0]),
		(C.size_t)(len(key)),
		(C.size_t)(outlen))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoGenericHashUpdate(state *C.struct_crypto_generichash_blake2b_state, in []byte) {
	if int(C.crypto_generichash_update(
		(state),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(len(in)))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoGenericHashFinal(state *C.struct_crypto_generichash_blake2b_state, outlen int) (out []byte) {
	CheckSizeInRange(outlen, CryptoGenericHashBytesMin(), CryptoGenericHashBytesMax(), "out")
	out = make([]byte, outlen)
	if int(C.crypto_generichash_final(
		state,
		(*C.uchar)(&out[0]),
		(C.size_t)(outlen))) != 0 {
		panic("see libsodium")
	}

	return
}
