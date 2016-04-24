package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoBoxSeedBytes      = int(C.crypto_box_seedbytes())
	cryptoBoxPublicKeyBytes = int(C.crypto_box_publickeybytes())
	cryptoBoxSecretKeyBytes = int(C.crypto_box_secretkeybytes())
	cryptoBoxSealBytes      = int(C.crypto_box_sealbytes())
	cryptoBoxNonceBytes     = int(C.crypto_box_noncebytes())
	cryptoBoxMacBytes       = int(C.crypto_box_macbytes())
)

type BoxKP struct {
	PublicKey BoxPublicKey
	SecretKey BoxSecretKey
}

type BoxPublicKey struct {
	Bytes
}

func (k BoxPublicKey) Size() int {
	return cryptoBoxPublicKeyBytes
}

type CommonKey struct {
	Bytes
}

func (k CommonKey) Size() int {
	return cryptoScalarmultBytes
}

type BoxSecretKey struct {
	Bytes
}

func (k BoxSecretKey) Size() int {
	return cryptoBoxSecretKeyBytes
}

//PublicKey calculates public key from BoxSecretKey.
func (k BoxSecretKey) PublicKey() BoxPublicKey {
	checkTypedSize(&k, "SecretKey")

	return BoxPublicKey(CryptoScalarmultBase(Scalar(k)))
}

//CommonKey calculates common key from BoxSecretKey and other's BoxPublicKey.
func (k BoxSecretKey) CommonKey(p BoxPublicKey) CommonKey {
	checkTypedSize(&p, "PublicKey")

	return CommonKey(CryptoScalarmult(Scalar(k), Scalar(p)))
}

type BoxSeed struct {
	Bytes
}

func (b BoxSeed) Size() int {
	return cryptoBoxSeedBytes
}

type BoxNonce struct {
	Bytes
}

func (n BoxNonce) Size() int {
	return cryptoBoxNonceBytes
}

func (b *BoxNonce) Next() {
	C.sodium_increment((*C.uchar)(&b.Bytes[0]), (C.size_t)(cryptoBoxNonceBytes))
}

type BoxMAC struct {
	Bytes
}

func (b BoxMAC) Size() int {
	return cryptoBoxMacBytes
}

//MakeBoxKP generates a keypair for Box
func MakeBoxKP() BoxKP {
	pkb := make([]byte, cryptoBoxPublicKeyBytes)
	skb := make([]byte, cryptoBoxSecretKeyBytes)
	if int(C.crypto_box_keypair(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&skb[0]))) != 0 {
		panic("see libsodium")
	}

	return BoxKP{
		BoxPublicKey{pkb},
		BoxSecretKey{skb},
	}
}

//SeedBoxKP generates a keypair for signing from a BoxSeed.
//
//The same pair of keys will be generated with the same 'seed'
func SeedBoxKP(seed BoxSeed) BoxKP {
	checkTypedSize(&seed, "seed")
	pkb := make([]byte, cryptoBoxPublicKeyBytes)
	skb := make([]byte, cryptoBoxSecretKeyBytes)
	if int(C.crypto_box_seed_keypair(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&skb[0]),
		(*C.uchar)(&seed.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return BoxKP{
		BoxPublicKey{pkb},
		BoxSecretKey{skb},
	}
}

//SealedBox puts message into a sealed box using receiver's PublicKey and an
//ephemeral key pair of which the SecretKey is destroyed on sender's side
//right after encryption, and the PublicKey is packed with the Box to the
//receiver.
//
//The receiver can open the box but can not verify the identity of the sender.
func (b Bytes) SealedBox(pk BoxPublicKey) (cm Bytes) {
	checkTypedSize(&pk, "PublicKey")
	cm = make([]byte, b.Length()+cryptoBoxSealBytes)
	if int(C.crypto_box_seal(
		(*C.uchar)(&cm[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&pk.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

//SealedBoxOpen reads message from a sealed box using its key pair and ephemeral
//public packed in the Box.
//
//It returns an error if opening failed.
func (b Bytes) SealedBoxOpen(kp BoxKP) (m Bytes, err error) {
	checkTypedSize(&kp.PublicKey, "receiver's PublicKey")
	checkTypedSize(&kp.SecretKey, "receiver's SecretKey")
	m = make([]byte, b.Length()-cryptoBoxSealBytes)
	if int(C.crypto_box_seal_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&kp.PublicKey.Bytes[0]),
		(*C.uchar)(&kp.SecretKey.Bytes[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

//Box puts message into an authenticated encrypted box using sender's SecretKey
//and receiver's PublicKey, with a shared one-time nonce is used for each
//message.
func (b Bytes) Box(n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (c Bytes) {
	checkTypedSize(&n, "nonce")
	checkTypedSize(&pk, "receiver's public key")
	checkTypedSize(&sk, "sender's secret key")
	c = make([]byte, b.Length()+cryptoBoxMacBytes)
	if int(C.crypto_box_easy(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&pk.Bytes[0]),
		(*C.uchar)(&sk.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return
}

//BoxOpen reads message from an authenticated encrypted box using receiver's
//SecretKey and sender's PublicKey with a shared one-time nonce
//
//It returns an error if opening failed.
func (b Bytes) BoxOpen(n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (m Bytes, err error) {
	checkTypedSize(&n, "nonce")
	checkTypedSize(&pk, "receiver's public key")
	checkTypedSize(&sk, "sender's secret key")
	m = make([]byte, b.Length()-cryptoBoxMacBytes)
	if int(C.crypto_box_open_easy(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&pk.Bytes[0]),
		(*C.uchar)(&sk.Bytes[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

//BoxDetached encodes message into an encrypted message using sender's SecretKey
//and receiver's PublicKey, with a shared one-time nonce is used for each
//message.
//
//Detached MAC is return along with encrypted message for authentication.
func (b Bytes) BoxDetached(n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (mac BoxMAC, c Bytes) {
	checkTypedSize(&n, "nonce")
	checkTypedSize(&pk, "receiver's public key")
	checkTypedSize(&sk, "sender's secret key")
	c = make([]byte, b.Length())
	macb := make([]byte, cryptoBoxMacBytes)
	if int(C.crypto_box_detached(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&macb[0]),
		(*C.uchar)(&b[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&pk.Bytes[0]),
		(*C.uchar)(&sk.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return BoxMAC{macb}, c
}

//BoxOpenDetached decodes message from an encrypted message along with a MAC for
//authentication, and using receiver's SecretKey and sender's PublicKey with
// a shared one-time nonce.
//
//It returns an error if opening failed.
func (b Bytes) BoxOpenDetached(mac BoxMAC, n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (m Bytes, err error) {
	checkTypedSize(&mac, "MAC")
	checkTypedSize(&n, "nonce")
	checkTypedSize(&pk, "receiver's public key")
	checkTypedSize(&sk, "sender's secret key")
	m = make([]byte, b.Length())
	if int(C.crypto_box_open_detached(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&b[0]),
		(*C.uchar)(&mac.Bytes[0]),
		(C.ulonglong)(b.Length()),
		(*C.uchar)(&n.Bytes[0]),
		(*C.uchar)(&pk.Bytes[0]),
		(*C.uchar)(&sk.Bytes[0]))) != 0 {
		err = ErrOpenBox
	}

	return
}

