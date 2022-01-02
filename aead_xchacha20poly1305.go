package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoAEADXChaCha20Poly1305IETFKeyBytes  = int(C.crypto_aead_xchacha20poly1305_ietf_keybytes())
	cryptoAEADXChaCha20Poly1305IETFNPubBytes = int(C.crypto_aead_xchacha20poly1305_ietf_npubbytes())
	cryptoAEADXChaCha20Poly1305IETFABytes    = int(C.crypto_aead_xchacha20poly1305_ietf_abytes())
)

type AEADXCPNonce struct {
	Bytes
}

func (AEADXCPNonce) Size() int {
	return cryptoAEADXChaCha20Poly1305IETFNPubBytes
}

func (n *AEADXCPNonce) Next() {
	C.sodium_increment((*C.uchar)(&n.Bytes[0]), (C.size_t)(cryptoAEADChaCha20Poly1305IETFNPubBytes))
}

type AEADXCPKey struct {
	Bytes
}

func MakeAEADXCPKey() AEADXCPKey {
	b := make([]byte, cryptoAEADXChaCha20Poly1305IETFKeyBytes);
	C.crypto_aead_xchacha20poly1305_ietf_keygen((*C.uchar)(&b[0]))
	return AEADXCPKey{b}
}

func (AEADXCPKey) Size() int {
	return cryptoAEADXChaCha20Poly1305IETFKeyBytes
}

type AEADXCPMAC struct {
	Bytes
}

func (AEADXCPMAC) Size() int {
	return cryptoAEADXChaCha20Poly1305IETFABytes
}

//AEADXCPEncrypt encrypts message with AEADXCPKey, and AEADXCPNonce.
//Message then authenticated with additional data 'ad'.
//Authentication tag is append to the encrypted data.
func (b Bytes) AEADXCPEncrypt(ad Bytes, n AEADXCPNonce, k AEADXCPKey) (c Bytes) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")

	bp, bl := plen(b)
	c = make([]byte, bl+cryptoAEADXChaCha20Poly1305IETFABytes)
	cp, _ := plen(c)

	var outlen C.ulonglong

	adp, adl := plen(ad)

	if int(C.crypto_aead_xchacha20poly1305_ietf_encrypt(
		(*C.uchar)(cp),
		&outlen,
		(*C.uchar)(bp),
		(C.ulonglong)(bl),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		(*C.uchar)(nil),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	c = c[:outlen]

	return
}

//AEADXCPDecrypt decrypts message with AEADXCPKey, and AEADXCPNonce.
//The appended authenticated tag is verified with additional data 'ad' before decryption.
//
//It returns an error if decryption failed.
func (b Bytes) AEADXCPDecrypt(ad Bytes, n AEADXCPNonce, k AEADXCPKey) (m Bytes, err error) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")
	bp, bl := plen(b)
	m = make([]byte, bl-cryptoAEADXChaCha20Poly1305IETFABytes)
	mp, _ := plen(m)
	adp, adl := plen(ad)

	var outlen C.ulonglong

	if int(C.crypto_aead_xchacha20poly1305_ietf_decrypt(
		(*C.uchar)(mp),
		&outlen,
		(*C.uchar)(nil),
		(*C.uchar)(bp),
		(C.ulonglong)(bl),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	m = m[:outlen]
	return
}

//AEADXCPEncryptDetached encrypts message with AEADXCPKey, and AEADXCPNonce.
//Message then authenticated with additional data 'ad'.
//Authentication tag is separated saved as 'mac'.
func (b Bytes) AEADXCPEncryptDetached(ad Bytes, n AEADXCPNonce, k AEADXCPKey) (c Bytes, mac AEADXCPMAC) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")

	bp, bl := plen(b)
	adp, adl := plen(ad)

	c = make([]byte, b.Length())
	cp, _ := plen(c)

	macb := make([]byte, cryptoAEADXChaCha20Poly1305IETFABytes)
	var outlen C.ulonglong

	if int(C.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
		(*C.uchar)(cp),
		(*C.uchar)(&macb[0]),
		&outlen,
		(*C.uchar)(bp),
		(C.ulonglong)(bl),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		(*C.uchar)(nil),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	mac = AEADXCPMAC{macb[:outlen]}
	return
}

//AEADXCPDecryptDetached decrypts message with AEADXCPKey, and AEADXCPNonce.
//The separated authenticated tag is verified with additional data 'ad' before decryption.
//
//It returns an error if decryption failed.
func (b Bytes) AEADXCPDecryptDetached(mac AEADXCPMAC, ad Bytes, n AEADXCPNonce, k AEADXCPKey) (m Bytes, err error) {
	checkTypedSize(&mac, "public mac")
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")

	bp, bl := plen(b)
	adp, adl := plen(ad)
	m = make([]byte, bl)
	mp, _ := plen(m)
	if int(C.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
		(*C.uchar)(mp),
		(*C.uchar)(nil),
		(*C.uchar)(bp),
		(C.ulonglong)(bl),
		(*C.uchar)(&mac.Bytes[0]),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	return
}

//AEADXCPVerify decrypts message with AEADXCPKey, and AEADXCPNonce without writing decrypted data.
//The appended authenticated tag is verified with additional data 'ad' before decryption.
//
//It returns an error if decryption failed.
func (b Bytes) AEADXCPVerify(ad Bytes, n AEADXCPNonce, k AEADXCPKey) (err error) {
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")

	bp, bl := plen(b)
	adp, adl := plen(ad)

	if int(C.crypto_aead_xchacha20poly1305_ietf_decrypt(
		(*C.uchar)(nil),
		(*C.ulonglong)(nil),
		(*C.uchar)(nil),
		(*C.uchar)(bp),
		(C.ulonglong)(bl),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	return
}

//AEADXCPVerifyDetached decrypts message with AEADXCPKey, and AEADXCPNonce without writing decrypted data.
//The separated authenticated tag is verified with additional data 'ad' before decryption.
//
//It returns an error if decryption failed.
func (b Bytes) AEADXCPVerifyDetached(mac AEADXCPMAC, ad Bytes, n AEADXCPNonce, k AEADXCPKey) (err error) {
	checkTypedSize(&mac, "public mac")
	checkTypedSize(&n, "public nonce")
	checkTypedSize(&k, "secret key")

	bp, bl := plen(b)
	adp, adl := plen(ad)

	if int(C.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
		(*C.uchar)(nil),
		(*C.uchar)(nil),
		(*C.uchar)(bp),
		(C.ulonglong)(bl),
		(*C.uchar)(&mac.Bytes[0]),
		(*C.uchar)(adp),
		(C.ulonglong)(adl),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrDecryptAEAD
	}
	return
}
