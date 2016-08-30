package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoAuthBytes    = int(C.crypto_auth_bytes())
	cryptoAuthKeyBytes = int(C.crypto_auth_keybytes())
)

type MACKey struct {
	Bytes
}

func (b MACKey) Size() int {
	return cryptoAuthKeyBytes
}

//MAC stores Message Authentication Code produced by HMAC-SHA512256.
type MAC struct {
	Bytes
}

func (b MAC) Size() int {
	return cryptoAuthBytes
}

//Auth generates a MAC for the message with the secret 'key'.
func (b Bytes) Auth(key MACKey) (mac MAC) {
	checkTypedSize(&key, "Secret Key")
	o := make([]byte, cryptoAuthBytes)

	if int(C.crypto_auth(
		(*C.uchar)(&o[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	mac = MAC{o}

	return
}

//AuthVerify verifies a messagee with MAC and the secret 'key'.
//
//It returns an error if verification failed.
func (b Bytes) AuthVerify(mac MAC, key MACKey) (err error) {
	checkTypedSize(&key, "Secret Key")
	checkTypedSize(&mac, "MAC")
	if int(C.crypto_auth_verify(
		(*C.uchar)(&mac.Bytes[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		err = ErrAuth
	}

	return
}
