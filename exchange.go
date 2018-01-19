package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoKXPublicKeyBytes  = int(C.crypto_kx_publickeybytes())
	cryptoKXSecretKeyBytes  = int(C.crypto_kx_secretkeybytes())
	cryptoKXSeedBytes       = int(C.crypto_kx_seedbytes())
	cryptoKXSessionKeyBytes = int(C.crypto_kx_sessionkeybytes())
)

type KXKP struct {
	PublicKey KXPublicKey
	SecretKey KXSecretKey
}

//MakeKXKP generates a keypair for signing
func MakeKXKP() KXKP {
	pkb := make([]byte, cryptoKXPublicKeyBytes)
	skb := make([]byte, cryptoKXSecretKeyBytes)
	if int(C.crypto_kx_keypair(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&skb[0]))) != 0 {
		panic("see libsodium")
	}

	return KXKP{
		KXPublicKey{pkb},
		KXSecretKey{skb},
	}
}

//SeedKXKP generates a keypair for exchanging from a KXSeed.
//
//The same pair of keys will be generated with the same 'seed'
func SeedKXKP(seed KXSeed) KXKP {
	checkTypedSize(&seed, "seed")
	pkb := make([]byte, cryptoKXPublicKeyBytes)
	skb := make([]byte, cryptoKXSecretKeyBytes)
	if int(C.crypto_kx_seed_keypair(
		(*C.uchar)(&pkb[0]),
		(*C.uchar)(&skb[0]),
		(*C.uchar)(&seed.Bytes[0]))) != 0 {
		panic("see libsodium")
	}

	return KXKP{
		KXPublicKey{pkb},
		KXSecretKey{skb},
	}
}

// ClientSessionKeys calculates Rx (for receving) and Tx (for sending) session keys
// with server's public key.
// return error when server_pk is not acceptable.
func (kp KXKP) ClientSessionKeys(server_pk KXPublicKey) (*KXSessionKeys, error) {
	checkTypedSize(&kp.PublicKey, "Client Public Key")
	checkTypedSize(&kp.SecretKey, "Client Secret Key")
	checkTypedSize(&server_pk, "Server Public Key")

	rxb := make([]byte, cryptoKXSessionKeyBytes)
	txb := make([]byte, cryptoKXSessionKeyBytes)
	if int(C.crypto_kx_client_session_keys(
		(*C.uchar)(&rxb[0]),
		(*C.uchar)(&txb[0]),
		(*C.uchar)(&kp.PublicKey.Bytes[0]),
		(*C.uchar)(&kp.SecretKey.Bytes[0]),
		(*C.uchar)(&server_pk.Bytes[0]))) != 0 {
		return nil, ErrInvalidKey
	}

	return &KXSessionKeys{
		Rx: KXSessionKey{rxb},
		Tx: KXSessionKey{txb},
	}, nil
}

// ServerSessionKeys calculates Rx (for receving) and Tx (for sending) session keys
// with client's public key.
// return error when client_pk is not acceptable.
func (kp KXKP) ServerSessionKeys(client_pk KXPublicKey) (*KXSessionKeys, error) {
	checkTypedSize(&kp.PublicKey, "Server Public Key")
	checkTypedSize(&kp.SecretKey, "Server Secret Key")
	checkTypedSize(&client_pk, "Client Public Key")

	rxb := make([]byte, cryptoKXSessionKeyBytes)
	txb := make([]byte, cryptoKXSessionKeyBytes)
	if int(C.crypto_kx_server_session_keys(
		(*C.uchar)(&rxb[0]),
		(*C.uchar)(&txb[0]),
		(*C.uchar)(&kp.PublicKey.Bytes[0]),
		(*C.uchar)(&kp.SecretKey.Bytes[0]),
		(*C.uchar)(&client_pk.Bytes[0]))) != 0 {
		return nil, ErrInvalidKey
	}

	return &KXSessionKeys{
		Rx: KXSessionKey{rxb},
		Tx: KXSessionKey{txb},
	}, nil
}

type KXSessionKeys struct {
	Rx KXSessionKey
	Tx KXSessionKey
}

type KXPublicKey struct {
	Bytes
}

func (k KXPublicKey) Size() int {
	return cryptoKXPublicKeyBytes
}

type KXSecretKey struct {
	Bytes
}

func (k KXSecretKey) Size() int {
	return cryptoKXSecretKeyBytes
}

type KXSessionKey struct {
	Bytes
}

func (k KXSessionKey) Size() int {
	return cryptoKXSessionKeyBytes
}

type KXSeed struct {
	Bytes
}

func (k KXSeed) Size() int {
	return cryptoKXSeedBytes
}
