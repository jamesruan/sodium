package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoAuthBytes() int {
	return int(C.crypto_auth_bytes())
}

func CryptoAuthKeyBytes() int {
	return int(C.crypto_auth_keybytes())
}

func CryptoAuthPrimitive() string {
	return C.GoString(C.crypto_auth_primitive())
}

func CryptoAuth(in []byte, key []byte) (out []byte) {
	CheckSize(key, CryptoAuthKeyBytes(), "key")
	inlen := len(in)
	out = make([]byte, inlen + CryptoAuthBytes())

	if int(C.crypto_auth(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(inlen),
		(*C.uchar)(&key[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoAuthVerify(hmac []byte, in []byte, key []byte) (err error) {
	CheckSize(key, CryptoAuthKeyBytes(), "key")
	inlen := len(in)

	if int(C.crypto_auth_verify(
		(*C.uchar)(&hmac[0]),
		(*C.uchar)(&in[0]),
		(C.ulonglong)(inlen),
		(*C.uchar)(&key[0]))) != 0 {
		err = ErrAuth
	}

	return
}
