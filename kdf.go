package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "unsafe"

var (
	cryptoKDFKeyBytes     = int(C.crypto_kdf_keybytes())
	CryptoKDFBytesMin     = int(C.crypto_kdf_bytes_min())
	CryptoKDFBytesMax     = int(C.crypto_kdf_bytes_max())
	CryptoKDFContextBytes = int(C.crypto_kdf_contextbytes())
)

// MasterKey for deriving SubKeys
type MasterKey struct {
	Bytes
}

func (MasterKey) Size() int {
	return cryptoKDFKeyBytes
}

func (m MasterKey) Length() int {
	return len(m.Bytes)
}

// MakeMasterKey generates a new MasterKey
func MakeMasterKey() MasterKey {
	mk := make([]byte, cryptoKDFKeyBytes)
	C.crypto_kdf_keygen((*C.uchar)(&mk[0]))
	return MasterKey{mk}
}

// SubKey derived from a MasterKey
type SubKey struct {
	Bytes
}

func (SubKey) Size() int {
	return CryptoKDFBytesMax
}

// KeyContext is a CryptoKDFContextBytes length string indicating
// the context for the key. e.g. "username"
type KeyContext string

func (k KeyContext) Length() int {
	return len(k)
}

func (KeyContext) Size() int {
	return CryptoKDFContextBytes
}

func (k *KeyContext) setBytes(b Bytes) {
	s := make([]byte, CryptoKDFContextBytes)
	copy(s, b)
	*k = KeyContext(s)
}

func MakeKeyContext(s string) KeyContext {
	c := new(KeyContext)
	c.setBytes(Bytes(s))
	return *c
}

// Derive SubKey from the MasterKey
// length should be between CryptoKDFBytesMin and CryptoKDFBytesMax
func (m MasterKey) Derive(length int, id uint64, context KeyContext) SubKey {
	checkSizeInRange(length, CryptoKDFBytesMin, CryptoKDFBytesMax, "deriving subkey")
	checkTypedSize(&context, "key context")
	sk := make([]byte, length)
	ctxc := C.CString(string(context))
	defer C.free(unsafe.Pointer(ctxc))

	if int(C.crypto_kdf_derive_from_key(
		(*C.uchar)(&sk[0]),
		(C.size_t)(length),
		(C.uint64_t)(id),
		ctxc,
		(*C.uchar)(&m.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return SubKey{sk}
}
