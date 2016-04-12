package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoSignBytes() int {
	return int(C.crypto_sign_bytes())
}

func CryptoSignSeedBytes() int {
	return int(C.crypto_sign_seedbytes())
}

func CryptoSignPublicKeyBytes() int {
	return int(C.crypto_sign_publickeybytes())
}

func CryptoSignSecretKeyBytes() int {
	return int(C.crypto_sign_secretkeybytes())
}

func CryptoSignPrimitive() string {
	return C.GoString(C.crypto_sign_primitive())
}

func CryptoSignSeedKeyPair(seed []byte) (sk []byte, pk []byte) {
	CheckSize(seed, CryptoSignSeedBytes(), "seed")
	sk = make([]byte, CryptoSignSecretKeyBytes())
	pk = make([]byte, CryptoSignPublicKeyBytes())
	if int(C.crypto_sign_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoSignKeyPair() (sk []byte, pk []byte) {
	sk = make([]byte, CryptoSignSecretKeyBytes())
	pk = make([]byte, CryptoSignPublicKeyBytes())
	if int(C.crypto_sign_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoSign(m []byte, sk []byte) (sm[]byte) {
	CheckSize(sk, CryptoSignSecretKeyBytes(), "secret key")
	sm = make([]byte, len(m)+CryptoSignBytes())
	var smlen C.ulonglong

	if int(C.crypto_sign(
		(*C.uchar)(&sm[0]),
		&smlen,
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}
	sm = sm[:smlen]

	return
}

func CryptoSignOpen(sm []byte, pk []byte) (m []byte, err error) {
	CheckSize(pk, CryptoSignPublicKeyBytes(), "public key")
	m = make([]byte, len(sm)-CryptoSignBytes())
	var mlen C.ulonglong

	if int(C.crypto_sign_open(
		(*C.uchar)(&m[0]),
		&mlen,
		(*C.uchar)(&sm[0]),
		(C.ulonglong)(len(sm)),
		(*C.uchar)(&pk[0]))) != 0 {
		err = ErrOpenSign
	}
	m = m[:mlen]
	return
}

func CryptoSignDetached(m []byte, sk []byte) (sig []byte) {
	CheckSize(sk, CryptoSignSecretKeyBytes(), "secret key")
	sig = make([]byte, CryptoSignBytes())
	var siglen C.ulonglong

	if int(C.crypto_sign_detached(
		(*C.uchar)(&sig[0]),
		&siglen,
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}
	sig = sig[:siglen]

	return
}

func CryptoSignVerifyDetached(sig []byte, m []byte, pk []byte) (err error) {
	CheckSize(sig, CryptoSignBytes(), "signature")
	CheckSize(pk, CryptoSignPublicKeyBytes(), "public key")

	if int(C.crypto_sign_verify_detached(
		(*C.uchar)(&sig[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&pk[0]))) != 0 {
		err = ErrOpenSign
	}
	return 
}
