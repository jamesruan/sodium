package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoSignBytes          = int(C.crypto_sign_bytes())
	cryptoSignSeedBytes      = int(C.crypto_sign_seedbytes())
	cryptoSignPublicKeyBytes = int(C.crypto_sign_publickeybytes())
	cryptoSignSecretKeyBytes = int(C.crypto_sign_secretkeybytes())
	cryptoSignPrimitive      = C.GoString(C.crypto_sign_primitive())
)

type SignKP struct {
	PublicKey SignPublicKey
	SecretKey SignSecretKey
}

//MakeSignKP generates a keypair for signing
func MakeSignKP() SignKP {
	pkb := make([]byte, cryptoSignPublicKeyBytes)
	skb := make([]byte, cryptoSignSecretKeyBytes)
	if int(C.crypto_sign_keypair(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&skb[0]))) != 0 {
		panic("see libsodium")
	}

	return SignKP {
		SignPublicKey{pkb},
		SignSecretKey{skb},
	}
}

//SeedSignKP generates a keypair for signing from a SignSeed.
//
//The same pair of keys will be generated with the same 'seed'
func SeedSignKP(seed SignSeed) SignKP {
	checkTypedSize(&seed, "seed")
	pkb := make([]byte, cryptoSignPublicKeyBytes)
	skb := make([]byte, cryptoSignSecretKeyBytes)
	if int(C.crypto_sign_seed_keypair(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&skb[0]),
		(*C.uchar)(&seed.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return SignKP {
		SignPublicKey{pkb},
		SignSecretKey{skb},
	}
}

//extracts the BoxSecretKey from the SignSecretKey.
func (k SignSecretKey) BoxSecret() BoxSecretKey {
	checkTypedSize(&k, "Sign SecretKey")
	pkb := make([]byte, cryptoBoxSecretKeyBytes)
	C.crypto_sign_ed25519_sk_to_curve25519(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&k.Bytes[0]))
	return BoxSecretKey{pkb}
}

//extracts the BoxPublicKey from the SignPublicKey.
func (k SignPublicKey) BoxPublic() BoxPublicKey {
	checkTypedSize(&k, "Sign PublicKey")
	pkb := make([]byte, cryptoBoxPublicKeyBytes)
	C.crypto_sign_ed25519_pk_to_curve25519(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&k.Bytes[0]))
	return BoxPublicKey{pkb}
}

//Generate BoxKeyPair from SignKeyPair
func (p SignKP) MakeBoxKP() BoxKP{
		return BoxKP{
				p.PublicKey.BoxPublic(),
				p.SecretKey.BoxSecret(),
		}
}

type SignSeed struct {
	Bytes
}

func (k SignSeed) Size() int {
	return cryptoSignSeedBytes
}

type SignSecretKey struct {
	Bytes
}

func (k SignSecretKey) Size() int {
	return cryptoSignSecretKeyBytes
}

//Seed extracts the seed used when generating the key pair.
func (k SignSecretKey) Seed() SignSeed {
	checkTypedSize(&k, "Sign SecretKey")
	sb := make([]byte, cryptoSignSeedBytes)
	C.crypto_sign_ed25519_sk_to_seed(
		(*C.uchar)(&sb[0]),
		(*C.uchar)(&k.Bytes[0]))
	return SignSeed{sb}
}

//PublicKey extracts the SignPublicKey from the SignSecretKey.
func (k SignSecretKey) PublicKey() SignPublicKey {
	checkTypedSize(&k, "Sign SecretKey")
	pkb := make([]byte, cryptoSignPublicKeyBytes)
	C.crypto_sign_ed25519_sk_to_pk(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&k.Bytes[0]))
	return SignPublicKey{pkb}
}

type SignPublicKey struct {
	Bytes
}

func (k SignPublicKey) Size() int {
	return cryptoSignPublicKeyBytes
}

type Signature struct {
	Bytes
}

func (b Signature) Size() int {
	return cryptoSignBytes
}

//Sign returns 'sm': signature+message
func (b Bytes) Sign(key SignSecretKey) (sm Bytes) {
	checkTypedSize(&key, "Sign SecretKey")
	sm = make([]byte, b.Length()+cryptoSignBytes)
	var smlen C.ulonglong

	if int(C.crypto_sign(
		(*C.uchar)(&sm[0]),
		&smlen,
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	sm = sm[:smlen]

	return
}

//SignDetached signs the message with 'key' and returns only the signature.
func (b Bytes) SignDetached(key SignSecretKey) (sig Signature) {
	checkTypedSize(&key, "Sign SecretKey")
	sigb := make([]byte, cryptoSignBytes)
	var siglen C.ulonglong

	if int(C.crypto_sign_detached(
		(*C.uchar)(&sigb[0]),
		&siglen,
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		panic("see libsodium")
	}
	sig = Signature{sigb[:siglen]}

	return
}

//SignVerifyDetached verifies the message and its detached 'sig' with 'key'.
//
//It returns an error if verification failed.
func (b Bytes) SignVerifyDetached(sig Signature, key SignPublicKey) (err error) {
	checkTypedSize(&sig, "Signature")
	checkTypedSize(&key, "Sign PublicKey")
	if int(C.crypto_sign_verify_detached(
		(*C.uchar)(&sig.Bytes[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		err = ErrOpenSign
	}
	return
}

//SignOpen returns message 'm' from signature+message, verified by 'key'.
//
//It returns an error if verification failed.
func (b Bytes) SignOpen(key SignPublicKey) (m Bytes, err error) {
	checkTypedSize(&key, "Sign PublicKey")
	m = make([]byte, b.Length()-cryptoSignBytes)
	var mlen C.ulonglong

	if int(C.crypto_sign_open(
		(*C.uchar)(&m[0]),
		&mlen,
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&key.Bytes[0]))) != 0 {
		err = ErrOpenSign
	}
	m = m[:mlen]
	return
}
