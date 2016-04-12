package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoSecretBoxKeyBytes() int {
	return int(C.crypto_secretbox_keybytes())
}

func CryptoSecretBoxNonceBytes() int {
	return int(C.crypto_secretbox_noncebytes())
}

func CryptoSecretBoxZeroBytes() int {
	return int(C.crypto_secretbox_zerobytes())
}

func CryptoSecretBoxBoxZeroBytes() int {
	return int(C.crypto_secretbox_boxzerobytes())
}

func CryptoSecretBoxMacBytes() int {
	return int(C.crypto_secretbox_macbytes())
}

func CryptoSecretBoxPrimitive() string {
	return C.GoString(C.crypto_secretbox_primitive())
}

func CryptoSecretBox(m []byte, n []byte, k []byte) (c []byte) {
	CheckSize(n, CryptoSecretBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoSecretBoxKeyBytes(), "key")
	c = make([]byte, len(m)+CryptoSecretBoxMacBytes())
	if int(C.crypto_secretbox(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoSecretBoxOpen(c []byte, n []byte, k []byte) (m []byte, err error) {
	CheckSize(n, CryptoSecretBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoSecretBoxKeyBytes(), "key")
	m = make([]byte, len(c)-CryptoSecretBoxMacBytes())
	if int(C.crypto_secretbox_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}
