package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoBoxSeal(m []byte, pk []byte) (c []byte) {
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	c = make([]byte, len(m)+CryptoBoxMacBytes())
	if int(C.crypto_box_seal(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&pk[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxSealOpen(c []byte, pk []byte, sk []byte) (m []byte, err error) {
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	m = make([]byte, len(c)-CryptoBoxMacBytes())
	if int(C.crypto_box_seal_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

func CryptoBoxSealBytes() int {
	return int(C.crypto_box_sealbytes())
}
