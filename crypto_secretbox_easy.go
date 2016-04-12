package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoSecretBoxDetached(m []byte, n []byte, k []byte) (c []byte, mac[]byte) {
	CheckSize(n, CryptoSecretBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoSecretBoxKeyBytes(), "key")
	c = make([]byte, len(m))
	mac = make([]byte, CryptoSecretBoxMacBytes())
	if int(C.crypto_secretbox_detached(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoSecretBoxOpenDetached(c []byte, mac []byte, n []byte, k []byte) (m []byte, err error) {
	CheckSize(mac, CryptoSecretBoxMacBytes(), "mac")
	CheckSize(n, CryptoSecretBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoSecretBoxKeyBytes(), "key")
	m = make([]byte, len(c))
	if int(C.crypto_secretbox_open_detached(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

func CryptoSecretBoxEasy(m []byte, n []byte, k []byte) (c []byte) {
	CheckSize(n, CryptoSecretBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoSecretBoxKeyBytes(), "key")
	c = make([]byte, len(m)+CryptoSecretBoxMacBytes())
	if int(C.crypto_secretbox_easy(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoSecretBoxOpenEasy(c []byte, n []byte, k []byte) (m []byte, err error) {
	CheckSize(n, CryptoSecretBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoSecretBoxKeyBytes(), "key")
	m = make([]byte, len(c)-CryptoSecretBoxMacBytes())
	if int(C.crypto_secretbox_open_easy(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}
