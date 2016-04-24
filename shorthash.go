package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoShortHashBytes    = int(C.crypto_shorthash_bytes())
	cryptoShortHashKeyBytes = int(C.crypto_shorthash_keybytes())
)

type ShortHash struct {
	Bytes
}
func (s ShortHash) Size() int {
	return cryptoShortHashBytes
}

type ShortHashKey struct {
	Bytes
}
func (s ShortHashKey) Size() int {
	return cryptoShortHashKeyBytes
}

//Shorthash use a secret key and input to produce a ShortHash.
//It is protective to short input. And it's output is also too short to
//be collision-resistent, however it can be used in hash table, Bloom filter
//or generate MAC for interactive protocol.
func (b Bytes) Shorthash(key ShortHashKey) (out Bytes) {
	checkTypedSize(&key, "key")

	out = make([]byte, cryptoShortHashBytes)
	if int(C.crypto_shorthash(
		(*C.uchar)(&out[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return
}
