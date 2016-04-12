package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoScalarmultBytes() int {
	return int(C.crypto_scalarmult_bytes())
}

func CryptoScalarmultScalarBytes() int {
	return int(C.crypto_scalarmult_scalarbytes())
}

func CryptoScalarmultPrimitive() string {
	return C.GoString(C.crypto_scalarmult_primitive())
}

func CryptoScalarmultBase(n []byte) (q []byte) {
	CheckSize(n, CryptoScalarmultScalarBytes(), "secret key")
	q = make([]byte, CryptoScalarmultBytes())

	if int(C.crypto_scalarmult_base(
		(*C.uchar)(&q[0]),
		(*C.uchar)(&n[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoScalarMult(n []byte, p []byte) (q []byte) {
	CheckSize(n, CryptoScalarmultScalarBytes(), "secret key")
	CheckSize(p, CryptoScalarmultScalarBytes(), "public key")
	q = make([]byte, CryptoScalarmultBytes())
	if int(C.crypto_scalarmult(
		(*C.uchar)(&q[0]),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&p[0]))) != 0 {
		panic("see libsodium")
	}

	return
}
