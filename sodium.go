//Package sodium is a wrapper for https://github.com/jedisct1/libsodium
//
//Most of the functions is a method to the "Bytes" type.
//They are grouped below:
//
//Signature
//
//Sender sign a message with its SecretKey and the receiver can verify the
//Signature by sender's PublicKey
//
//    type SignKP struct {
//        PublicKey SignPublicKey
//        SecretKey SignSecretKey
//    }
//    func MakeSignKP() SignKP
//    func SeedSignKP(seed SignSeed) SignKP
//    func (k SignSecretKey) PublicKey() SignPublicKey
//    func (k SignSecretKey) Seed() SignSeed
//
//    //SignKP can be converted to BoxKP, although it is recommended to use separate keys for signing and encrytion.
//    func (p SignKP) ToBox() BoxKP
//    func (k SignSecretKey) ToBox() BoxSecretKey
//    func (k SignPublicKey) ToBox() BoxPublicKey
//
//    //Message + Signature
//    func (b Bytes) Sign(key SignSecretKey) (sm Bytes)
//    func (b Bytes) SignOpen(key SignPublicKey) (m Bytes, err error)
//
//    //Detached Signature
//    func (b Bytes) SignDetached(key SignSecretKey) (sig Signature)
//    func (b Bytes) SignVerifyDetached(sig Signature, key SignPublicKey) (err error)
//
//(EdDSA25519)
//
//Anonymous Public Key Encryption
//
//An anonymous can encrypt a message with an ephemeral key pair and reveiver's
//PublicKey. The receiver can decrypt the message with its SecretKey but can not
//authenticates the sender.
//
//
//    type BoxKP struct {
//        PublicKey BoxPublicKey
//        SecretKey BoxSecretKey
//    }
//    func MakeBoxKP() BoxKP
//    func SeedBoxKP(seed BoxSeed) BoxKP
//
//    func (b Bytes) SealedBox(pk BoxPublicKey) (cm Bytes)
//    func (b Bytes) SealedBoxOpen(kp BoxKP) (m Bytes, err error)
//
//(X25519-XSalsa20-Poly1305)
//
//Authenticated Public Key Encryption
//
//Authenticated Box can be used to pass encrypt message from a known sender to a known receiver.
//
//A one-time shared nonce is also generated and passed to protect the key pairs and messages.
//
//    type BoxKP struct {
//        PublicKey BoxPublicKey
//        SecretKey BoxSecretKey
//    }
//    func MakeBoxKP() BoxKP
//    func SeedBoxKP(seed BoxSeed) BoxKP
//
//    func (b *BoxNonce) Next()
//
//    //All-in-one box
//    func (b Bytes) Box(n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (c Bytes)
//    func (b Bytes) BoxOpen(n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (m Bytes, err error)
//
//    //Detached MAC
//    func (b Bytes) BoxDetached(n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (mac BoxMAC, c Bytes)
//    func (b Bytes) BoxOpenDetached(mac BoxMAC, n BoxNonce, pk BoxPublicKey, sk BoxSecretKey) (c Bytes, err error)
//
//(X25519-XSalsa20-Poly1305)
//
//Diffie-Hellman Key Exchange
//
//BoxPublicKey can be calculated from BoxSecretKey:
//
//    //High-level function should be used most of the time.
//    func (k BoxSecretKey) PublicKey() BoxPublicKey
//
//    //Low-level function:
//    func CryptoScalarmultBase(n Scalar) (q Scalar)
//
//A CommonKey can be calculated from BoxSecretKey and other's BoxPublicKey:
//
//    //High-level function should be used most of the time.
//    func (k BoxSecretKey) CommonKey(p BoxPublicKey) CommonKey
//
//    //Low-level function.
//    func CryptoScalarmult(n, p Scalar) (q ScalarMult)
//
//(X25519)
//
//Secret Key Authentication
//
//One holder of a secret key authenticates message with MAC.
//
//Holders of the key can verify the message's authenticity.
//    func (b Bytes) Auth(key MACKey) (mac MAC)
//    func (b Bytes) AuthVerify(mac MAC, key MACKey) (err error)
//
//(HMAC-SHA512256)
//
//Secret Key Encryption
//
//Use a secret key and a nonce to protect the key, messages could be encrypted
//into a SecretBox
//
//    func (n *SecretBoxNonce) Next()
//
//    //encrypted message + MAC.
//    func (b Bytes) SecretBox(n SecretBoxNonce, k SecretBoxKey) (c Bytes)
//    func (b Bytes) SecretBoxOpen(n SecretBoxNonce, k SecretBoxKey) (m Bytes, err error)
//
//    //Detached version has a separate MAC.
//    func (b Bytes) SecretBoxDetached(n SecretBoxNonce, k SecretBoxKey) (c Bytes, mac SecretBoxMAC)
//    func (b Bytes) SecretBoxOpenDetached(mac SecretBoxMAC, n SecretBoxNonce, k SecretBoxKey) (m Bytes, err error)
//
//(XSalsa20-Poly1305)
//
//Authenticated Encryption with Additional Data
//
//Use a secret key and a nonce to protect the key, messages could be encrypted.
//Optional additional data and the message is authenticited with an authentication tag.
//
//Decryption not be performed before verify the authentication tag is verified.
//
//    func (n *AEADCPNonce) Next()
//
//    //encrypted message + MAC.
//    func (b Bytes) AEADCPEncrypt(ad Bytes, n AEADCPNonce, k AEADCPKey) (c Bytes)
//    func (b Bytes) AEADCPDecrypt(ad Bytes, n AEADCPNonce, k AEADCPKey) (m Bytes, err error)
//
//    //Detached version has a separate MAC.
//    func (b Bytes) AEADCPEncryptDetached(ad Bytes, n AEADCPNonce, k AEADCPKey) (c Bytes, mac AEADCPMAC)
//    func (b Bytes) AEADCPDecryptDetached(mac AEADCPMAC, ad Bytes, n AEADCPNonce, k AEADCPKey) (m Bytes, err error)
//
//AEADCP* (ChaCha20-Poly1305_IETF)
package sodium

import "errors"
import "fmt"
import "crypto/rand"

var (
	ErrAuth        = errors.New("sodium: Message forged")
	ErrOpenBox     = errors.New("sodium: Can't open box")
	ErrOpenSign    = errors.New("sodium: Signature forged")
	ErrDecryptAEAD = errors.New("sodium: Can't decrypt message")
	ErrPassword    = errors.New("sodium: Password not matched")
)

//Typed has pre-defined size.
type Typed interface {
	Size() int // Size returns the pre-defined size of the object.
	Length() int
	setBytes(Bytes)
}

//Bytes warppers around []byte.
type Bytes []byte

//Length returns the byte length.
func (b Bytes) Length() int {
	return len(b)
}

func (b *Bytes) setBytes(s Bytes) {
	*b = s[:]
}

//Nonce is used to protect secret key. It is important to not use the same nonce for a given key.
type Nonce interface {
	Typed
	Next() //Next unused nonce
}

//Randomize fill the Typed with random bytes.
func Randomize(k Typed) {
	b := make([]byte, k.Size())
	if _, err := rand.Read(b); err != nil {
		fmt.Println("error:", err)
		return
	}
	k.setBytes(b)
}
