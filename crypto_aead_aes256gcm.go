package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func CryptoAEADAES256GCMKeyBytes() int {
	return int(C.crypto_aead_aes256gcm_keybytes())
}

func CryptoAEADAES256GCMNSecBytes() int {
	return int(C.crypto_aead_aes256gcm_keybytes())
}

func CryptoAEADAES256GCMNPubBytes() int {
	return int(C.crypto_aead_aes256gcm_npubbytes())
}

func CryptoAEADAES256GCMABytes() int {
	return int(C.crypto_aead_aes256gcm_abytes())
}

func CryptoAEADAES256GCMStateBytes() int {
	return int(C.crypto_aead_aes256gcm_statebytes())
}

func CryptoAESAES256GCMIsAvailable() int {
	return int(C.crypto_aead_aes256gcm_is_available())
}

func CryptoAEADAES256GCMEncrypt(m []byte, ad []byte, nsec []byte, npub []byte, k []byte) (c []byte) {
	if CryptoAESAES256GCMIsAvailable() == 0 {
		panic("AES is not supported")
	}

	CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")
	CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")
	c = make([]byte, len(m)+CryptoAEADAES256GCMABytes())
	var outlen C.ulonglong

	if int(C.crypto_aead_aes256gcm_encrypt(
		(*C.uchar)(&c[0]),
		&outlen,
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&ad[0]),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(&nsec[0]),
		(*C.uchar)(&npub[0]),
		(*C.uchar)(&k[0]))) != 0 {
		panic("see libsodium")
	}
	c = c[:outlen]

	return
}

func CryptoAEADAES256GCMDecrypt(nsec []byte, c []byte, ad []byte, npub []byte, k []byte) (m []byte, err error) {
	if CryptoAESAES256GCMIsAvailable() == 0 {
		panic("AES is not supported")
	}

	CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")
	CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")
	m = make([]byte, len(c)-CryptoAEADAES256GCMABytes())
	var outlen C.ulonglong

	if int(C.crypto_aead_aes256gcm_decrypt(
		(*C.uchar)(&m[0]),
		&outlen,
		(*C.uchar)(&nsec[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&ad[0]),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(&npub[0]),
		(*C.uchar)(&k[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	m = m[:outlen]
	return
}
