package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"


func CryptoBoxSeedBytes() int {
	return int(C.crypto_box_seedbytes())
}

func CryptoBoxPublicKeyBytes() int {
	return int(C.crypto_box_publickeybytes())
}

func CryptoBoxSecretKeyBytes() int {
	return int(C.crypto_box_secretkeybytes())
}

func CryptoBoxNonceBytes() int {
	return int(C.crypto_box_noncebytes())
}

func CryptoBoxMacBytes() int {
	return int(C.crypto_box_macbytes())
}

func CryptoBoxPrimitive() string {
	return C.GoString(C.crypto_box_primitive())
}

func CryptoBoxBeforeNmBytes() int {
	return int(C.crypto_box_beforenmbytes())
}

func CryptoBoxZeroBytes() int {
	return int(C.crypto_box_zerobytes())
}

func CryptoBoxBoxZeroBytes() int {
	return int(C.crypto_box_boxzerobytes())
}

func CryptoBoxSeedKeyPair(seed []byte) (sk []byte, pk []byte) {
	CheckSize(seed, CryptoBoxSeedBytes(), "seed")
	sk = make([]byte, CryptoBoxSecretKeyBytes())
	pk = make([]byte, CryptoBoxPublicKeyBytes())
	if int(C.crypto_box_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0]))) !=0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxKeyPair() (sk []byte, pk []byte) {
	sk = make([]byte, CryptoBoxSecretKeyBytes())
	pk = make([]byte, CryptoBoxPublicKeyBytes())
	if int(C.crypto_box_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxBeforeNm(pk []byte, sk []byte) (k []byte) {
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "sender's secret key")
	k = make([]byte, CryptoBoxBeforeNmBytes())
	if int(C.crypto_box_beforenm(
		(*C.uchar)(&k[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBox(m []byte, n []byte, pk []byte, sk []byte) (c []byte) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "sender's secret key")
	c = make([]byte, len(m))
	if int(C.crypto_box(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxOpen(c []byte, n []byte, pk []byte, sk []byte) (m []byte, err error) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxPublicKeyBytes(), "secret key")
	m = make([]byte, len(c))
	if int(C.crypto_box_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

func CryptoBoxAfterNm(m []byte, n []byte, k []byte) (c []byte) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	c = make([]byte, len(m))
	if int(C.crypto_box_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxOpenAfterNm(c []byte, n []byte, k []byte) (m []byte, err error) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	m = make([]byte, len(c))
	if int(C.crypto_box_open_afternm(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) !=0 {
		err = ErrOpenBox
	}

	return
}
