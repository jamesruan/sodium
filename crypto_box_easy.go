package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoBoxDetachedAfterNm(mac []byte, m []byte, n []byte, k []byte) (c []byte) {
	CheckSize(mac, CryptoBoxMacBytes(), "mac")
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	c = make([]byte, len(m)+CryptoBoxMacBytes())
	if int(C.crypto_box_detached_afternm(
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

func CryptoBoxDetached(mac []byte, m []byte, n []byte, pk []byte, sk []byte) (c []byte) {
	CheckSize(mac, CryptoBoxMacBytes(), "mac")
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "sender's secret key")
	c = make([]byte, len(m)+CryptoBoxMacBytes())
	if int(C.crypto_box_detached(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxEasyAfterNm(m []byte, n []byte, k []byte) (c []byte) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	c = make([]byte, len(m)+CryptoBoxMacBytes())
	if int(C.crypto_box_easy_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

func CryptoBoxEasy(m []byte, n []byte, pk []byte, sk []byte) (c []byte) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	c = make([]byte, len(m)+CryptoBoxMacBytes())
	if int(C.crypto_box_easy(
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

func CryptoBoxOpenDetachedAfterNm(c []byte, mac []byte, n []byte, k []byte) (m []byte, err error) {
	CheckSize(mac, CryptoBoxMacBytes(), "mac")
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	m = make([]byte, len(c)-CryptoBoxMacBytes())
	if int(C.crypto_box_open_detached_afternm(
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

func CryptoBoxOpenDetached(c []byte, mac []byte, n []byte, pk []byte, sk []byte) (m []byte, err error) {
	CheckSize(mac, CryptoBoxMacBytes(), "mac")
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	m = make([]byte, len(c)-CryptoBoxMacBytes())
	if int(C.crypto_box_detached(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

func CryptoBoxOpenEasyAfterNm(c []byte, n []byte, k []byte) (m []byte, err error) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	m = make([]byte, len(c)-CryptoBoxMacBytes())
	if int(C.crypto_box_open_easy_afternm(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

func CryptoBoxOpenEasy(c []byte, n []byte, pk []byte, sk []byte) (m []byte, err error) {
	CheckSize(n, CryptoBoxNonceBytes(), "nonce")
	CheckSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	CheckSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	m = make([]byte, len(c)-CryptoBoxMacBytes())
	if int(C.crypto_box_easy(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))) !=0 {
		err = ErrOpenBox
	}

	return
}
