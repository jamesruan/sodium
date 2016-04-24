package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoSecretBoxKeyBytes     = int(C.crypto_secretbox_keybytes())
	cryptoSecretBoxNonceBytes   = int(C.crypto_secretbox_noncebytes())
	cryptoSecretBoxMacBytes     = int(C.crypto_secretbox_macbytes())
)

type SecretBoxKey struct {
	Bytes
}

func (s SecretBoxKey) Size() int {
	return cryptoSecretBoxKeyBytes
}

type SecretBoxNonce struct {
	Bytes
}

func (n SecretBoxNonce) Size() int {
	return cryptoSecretBoxNonceBytes
}

func (n *SecretBoxNonce) Next() {
	C.sodium_increment((*C.uchar)(&n.Bytes[0]), (C.size_t)(cryptoSecretBoxNonceBytes))
}

type SecretBoxMAC struct {
	Bytes
}

func (s SecretBoxMAC) Size() int {
	return cryptoSecretBoxMacBytes
}

//SecretBox use a SecretBoxNonce and a SecretBoxKey to encrypt a message.
func (b Bytes) SecretBox(n SecretBoxNonce, k SecretBoxKey) (c Bytes) {
	checkTypedSize(&n, "nonce")
	checkTypedSize(&k, "secret key")

	cb := make([]byte, b.Length()+cryptoSecretBoxMacBytes)
	if int(C.crypto_secretbox_easy(
		(*C.uchar)(&cb[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	c = Bytes(cb)

	return
}

//SecretBoxOpen opens a SecretBox using SecretBoxKey and SecretBoxNonce.
//
//It returns an error if opening failed.
func (b Bytes) SecretBoxOpen(n SecretBoxNonce, k SecretBoxKey) (m Bytes, err error) {
	checkTypedSize(&n, "nonce")
	checkTypedSize(&k, "secret key")
	mb := make([]byte, b.Length()-cryptoSecretBoxMacBytes)
	if int(C.crypto_secretbox_open_easy(
		(*C.uchar)(&mb[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrOpenBox
	}
	m = Bytes(mb)

	return
}

//SecretBoxDetached use a SecretBoxNonce and a SecretBoxKey to encrypt a message.
//A separate MAC is returned.
func (b Bytes) SecretBoxDetached(n SecretBoxNonce, k SecretBoxKey) (c Bytes, mac SecretBoxMAC) {
	checkTypedSize(&n, "nonce")
	checkTypedSize(&k, "secret key")
	cb := make([]byte, b.Length())
	macb := make([]byte, cryptoSecretBoxMacBytes)
	if int(C.crypto_secretbox_detached(
		(*C.uchar)(&cb[0]),
		(*C.uchar)(&macb[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	c = Bytes(cb)
	mac = SecretBoxMAC{macb}

	return
}

//SecretBoxOpenDetached opens a SecretBox using SecretBoxKey and SecretBoxNonce.
//with a separate MAC.
//
//It returns an error if opening failed.
func (b Bytes) SecretBoxOpenDetached(mac SecretBoxMAC, n SecretBoxNonce, k SecretBoxKey) (m Bytes, err error) {
	checkTypedSize(&mac, "mac")
	checkTypedSize(&n, "nonce")
	checkTypedSize(&k, "key")

	mb := make([]byte, b.Length())
	if int(C.crypto_secretbox_open_detached(
		(*C.uchar)(&mb[0]),
		(*C.uchar)(&b[0]),
		(*C.uchar)(&mac.Bytes[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&k.Bytes[0]))) != 0 {
		err = ErrOpenBox
	}
	m = Bytes(mb)

	return
}
