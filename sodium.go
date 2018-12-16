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
//    //SignKP can be converted to BoxKP
//    //It is recommended to use separate keys for signing and encrytion.
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
//(Ed25519)
//
//    //for multi-part messages that can't fit in memory
//    func MakeSignState() SignState
//    func (s SignState) Update(b []byte)
//    func (s SignState) Sign(key SignSecretKey) Signature
//    func (s SignState) Verify(sig Signature, key SignPublicKey) (err error)
//
//(Ed25519ph)
//
//Anonymous Public Key Encryption
//
//An anonymous can encrypt a message with an ephemeral key pair and reveiver's
//PublicKey. The receiver can decrypt the message with its SecretKey. Only the
//receiver is authenticated.
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
//The sender and the receiver are both authenticated to each other.
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
//Key Exchanging
//
//Server and Client exchange their public key and calculates a common session key with their own
//secret key.
//
//    type KXKP struct {
//        PublicKey KXPublicKey
//        SecretKey KXSecretKey
//    }
//    func MakeKXKP() KXKP
//    func SeedKXKP(seed KXSeed) KXKP
//
//    type KXSessionKeys struct {
//        Rx KXSessionKey
//        Tx KXSessionKey
//    }
//
//    // session keys for client
//    func (kp KXKP) ClientSessionKeys(server_pk KXPublicKey) (*KXSessionKeys, error)
//
//    // session keys for server
//    func (kp KXKP) ServerSessionKeys(client_pk KXPublicKey) (*KXSessionKeys, error) {
//    // client's rx == server's tx
//    // client's tx == server's rx
//
//(rx || tx = BLAKE2B-512(p.n || client_pk || server_pk))
//
//Secret Key Authentication
//
//One holder of a secret key authenticates the message with MAC.
//
//    //Holders of the key can generate a MAC for the message.
//    func (b Bytes) Auth(key MACKey) (mac MAC)
//    //Holders of the key can verify the message's authenticity.
//    func (b Bytes) AuthVerify(mac MAC, key MACKey) (err error)
//
//(HMAC-SHA512256)
//
//Secret Key Encryption
//
//Use a secret key and a nonce to protect the key, messages could be encrypted
//into a SecretBox. The encrypted data's intergrity is checked when decryption.
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
//Optional additional data and the message is authenticited with an
//authentication tag. Both intergrity and authenticity is checked when
//decryption. The decryption would not be performed unless the authentication
//tag is verified.
//
//    func (n *AEADCPNonce) Next()
//
//    //encrypted message + MAC.
//    func (b Bytes) AEADCPEncrypt(ad Bytes, n AEADCPNonce, k AEADCPKey) (c Bytes)
//    func (b Bytes) AEADCPDecrypt(ad Bytes, n AEADCPNonce, k AEADCPKey) (m Bytes, err error)
//    func (b Bytes) AEADCPVerify(ad Bytes, n AEADCPNonce, k AEADCPKey) (err error)
//
//    //Detached version has a separate MAC.
//    func (b Bytes) AEADCPEncryptDetached(ad Bytes, n AEADCPNonce, k AEADCPKey) (c Bytes, mac AEADCPMAC)
//    func (b Bytes) AEADCPDecryptDetached(mac AEADCPMAC, ad Bytes, n AEADCPNonce, k AEADCPKey) (m Bytes, err error)
//    func (b Bytes) AEADCPVerifyDetached(mac AEADCPMAC, ad Bytes, n AEADCPNonce, k AEADCPKey) (err error)
//
//AEADCP* (ChaCha20-Poly1305_IETF)
//
//Key Derivation
//
//Deriving subkeys from a single high-entropy key
//
//    func MakeMasterKey() MasterKey
//    func MakeKeyContext(s string) KeyContext
//    func (m MasterKey) Derive(length int, id uint64, context KeyContext) SubKey
//KDF (BLAKE2B)
package sodium

import (
	"crypto/rand"
	"errors"
	"fmt"
	"unsafe"
)

var (
	ErrAuth        = errors.New("sodium: Message forged")
	ErrOpenBox     = errors.New("sodium: Can't open box")
	ErrOpenSign    = errors.New("sodium: Signature forged")
	ErrDecryptAEAD = errors.New("sodium: Can't decrypt message")
	ErrPassword    = errors.New("sodium: Password not matched")
	ErrInvalidKey  = errors.New("sodium: Invalid key")
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

func (b Bytes) plen() (unsafe.Pointer, int) {
	if len(b) > 0 {
		return unsafe.Pointer(&b[0]), len(b)
	} else {
		return nil, 0
	}
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
