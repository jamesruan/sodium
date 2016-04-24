package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoAEADChaCha20Poly1305IETFKeyBytes  = int(C.crypto_aead_chacha20poly1305_ietf_keybytes())
	cryptoAEADChaCha20Poly1305IETFNPubBytes = int(C.crypto_aead_chacha20poly1305_ietf_npubbytes())
	cryptoAEADChaCha20Poly1305IETFABytes    = int(C.crypto_aead_chacha20poly1305_ietf_abytes())
)

type AEADCPNonce struct {
	Bytes
}

func (AEADCPNonce) Size() int {
	return cryptoAEADChaCha20Poly1305IETFNPubBytes
}

func (n *AEADCPNonce) Next() {
	C.sodium_increment((*C.uchar)(&n.Bytes[0]), (C.size_t)(cryptoAEADChaCha20Poly1305IETFNPubBytes))
}

type AEADCPKey struct {
	Bytes
}

func (AEADCPKey) Size() int {
	return cryptoAEADChaCha20Poly1305IETFKeyBytes
}

type AEADCPMAC struct {
	Bytes
}

func (AEADCPMAC) Size() int {
	return cryptoAEADChaCha20Poly1305IETFABytes
}

//AEADCPEncrypt encrypts message with AEADCPKey, and AEADCPNonce.
//Message then authenticated with additional data data 'ad'.
//Authentication tag is append to the encrypted data.
func (b Bytes) AEADCPEncrypt(ad Bytes, n AEADCPNonce, k AEADCPKey) (c Bytes) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")

	c = make([]byte, b.Length() + cryptoAEADChaCha20Poly1305IETFABytes)
	var outlen C.ulonglong

	if int(C.crypto_aead_chacha20poly1305_ietf_encrypt(
		(*C.uchar)(&c[0]),
		&outlen,
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&ad[0]),
		(C.ulonglong)(ad.Length()),
		(*C.uchar)(nil),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	c = c[:outlen]

	return
}

//AEADCPEncrypt decrypts message with AEADCPKey, and AEADCPNonce.
//The appended authenticated tag is verified with additional data 'ad' before decryption.
//
//It returns an error if decryption failed.
func (b Bytes) AEADCPDecrypt(ad Bytes, n AEADCPNonce, k AEADCPKey) (m Bytes, err error) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")
	m = make([]byte, b.Length() - cryptoAEADChaCha20Poly1305IETFABytes)
	var outlen C.ulonglong

	if int(C.crypto_aead_chacha20poly1305_ietf_decrypt(
		(*C.uchar)(&m[0]),
		&outlen,
		(*C.uchar)(nil),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&ad[0]),
		(C.ulonglong)(ad.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	m = m[:outlen]
	return
}

//AEADCPEncryptDetached encrypts message with AEADCPKey, and AEADCPNonce.
//Message then authenticated with additional data data 'ad'.
//Authentication tag is separated saved as 'mac'.
func (b Bytes) AEADCPEncryptDetached(ad Bytes, n AEADCPNonce, k AEADCPKey) (c Bytes, mac AEADCPMAC) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")
	c = make([]byte, b.Length())
	macb := make([]byte, cryptoAEADChaCha20Poly1305IETFABytes)
	var outlen C.ulonglong

	if int(C.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&macb[0]),
		&outlen,
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&ad[0]),
		(C.ulonglong)(ad.Length()),
		(*C.uchar)(nil),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	mac = AEADCPMAC{macb[:outlen]}
	return
}

//AEADCPEncryptDetached decrypts message with AEADCPKey, and AEADCPNonce.
//The separated authenticated tag is verified with additional data 'ad' before decryption.
//
//It returns an error if decryption failed.
func (b Bytes) AEADCPDecryptDetached(mac AEADCPMAC, ad Bytes, n AEADCPNonce, k AEADCPKey) (m Bytes, err error) {
	checkTypedSize(&mac, "public mac")
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")
	m = make([]byte, b.Length())

	if int(C.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
		(*C.uchar)(&m[0]),
		(*C.uchar)(nil),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&mac.Bytes[0]),
		(*C.uchar)(&ad[0]),
		(C.ulonglong)(ad.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	return
}
