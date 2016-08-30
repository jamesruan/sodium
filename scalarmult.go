package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoScalarmultBytes       = int(C.crypto_scalarmult_bytes())
	cryptoScalarmultScalarBytes = int(C.crypto_scalarmult_scalarbytes())
)

type Scalar struct {
	Bytes
}

func (s Scalar) Size() int {
	return cryptoScalarmultScalarBytes
}

//ScalarMult is the mulitiplication of two Scalar, used to calculate shared key
// from BoxSecertKey and other end's BoxPublicKey.
type ScalarMult struct {
	Bytes
}

func (s ScalarMult) Size() int {
	return cryptoScalarmultBytes
}

//CryptoScalarmultBase calculates BoxPublicKey 'q' from BoxSecertKey 'n'.
func CryptoScalarmultBase(n Scalar) (q Scalar) {
	checkTypedSize(&n, "SecretKey")
	qb := make([]byte, cryptoScalarmultScalarBytes)

	if int(C.crypto_scalarmult_base(
		(*C.uchar)(&qb[0]),
		(*C.uchar)(&n.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return Scalar{qb}
}

//CryptoScalarmult calculates common key 'q' from private key 'n' and
//other's public key 'p'
func CryptoScalarmult(n, p Scalar) (q ScalarMult) {
	checkTypedSize(&n, "SecretKey")
	checkTypedSize(&p, "PublicKey")

	qb := make([]byte, cryptoScalarmultBytes)
	if int(C.crypto_scalarmult(
		(*C.uchar)(&qb[0]),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&p.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return ScalarMult{qb}
}
