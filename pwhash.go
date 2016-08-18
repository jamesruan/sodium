package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

var (
	cryptoPWHashSaltBytes = int(C.crypto_pwhash_saltbytes())
	cryptoPWHashStrBytes = int(C.crypto_pwhash_strbytes())
	CryptoPWHashOpsLimitInteractive = int(C.crypto_pwhash_opslimit_interactive())
	CryptoPWHashMemLimitInteractive = int(C.crypto_pwhash_memlimit_interactive())
	CryptoPWHashOpsLimitModerate = int(C.crypto_pwhash_opslimit_moderate())
	CryptoPWHashMemLimitModerate = int(C.crypto_pwhash_memlimit_moderate())
	CryptoPWHashOpsLimitSensitive = int(C.crypto_pwhash_opslimit_sensitive())
	CryptoPWHashMemLimitSensitive = int(C.crypto_pwhash_memlimit_sensitive())

)

type PWHashSalt struct {
	Bytes
}

func (s PWHashSalt) Size() int {
	return cryptoPWHashSaltBytes
}

type PWHashStr struct {
	string
}

// NewPWHashStr constructs a PWHashStr for a string value.
func NewPWHashStr(value string) PWHashStr {
	return PWHashStr{value}
}

func PWHashDefault(t Typed, pw string, salt PWHashSalt) {
	PWHash(t, pw, salt, CryptoPWHashOpsLimitInteractive, CryptoPWHashMemLimitInteractive)
}

func PWHash(t Typed, pw string, salt PWHashSalt, opslimit int, memlimit int) {
	outlen := t.Size()
	if outlen < 16 {
		panic("output length too short")
	}

	s := make([]byte, outlen)
	pwc := C.CString(pw)

	if int(C.crypto_pwhash(
		(*C.uchar)(&s[0]),
		(C.ulonglong)(outlen),
		pwc,
		(C.ulonglong)(len(pw)),
		(*C.uchar)(&salt.Bytes[0]),
		(C.ulonglong)(opslimit),
		(C.size_t)(memlimit),
		C.crypto_pwhash_alg_default())) != 0 {
		panic("see libsodium")
	}

	t.setBytes(s)
}

//PWHashStore use moderate profile to pack hashed password into PWHashStr.
func PWHashStore(pw string) PWHashStr {
	s := make([]C.char, cryptoPWHashStrBytes)
	pwc := C.CString(pw)

	if int(C.crypto_pwhash_str(
		&s[0],
		pwc,
		(C.ulonglong)(len(pw)),
		(C.ulonglong)(CryptoPWHashOpsLimitModerate),
		(C.size_t)(CryptoPWHashMemLimitModerate))) != 0 {
		panic("see libsodium")
	}
	return PWHashStr{C.GoString(&s[0])}
}

//PWHashStoreSensitive use sensitive profile to pack hashed password into PWHashStr.
func PWHashStoreSensitive(pw string) PWHashStr {
	s := make([]C.char, cryptoPWHashStrBytes)
	pwc := C.CString(pw)

	if int(C.crypto_pwhash_str(
		&s[0],
		pwc,
		(C.ulonglong)(len(pw)),
		(C.ulonglong)(CryptoPWHashOpsLimitSensitive),
		(C.size_t)(CryptoPWHashMemLimitSensitive))) != 0 {
		panic("see libsodium")
	}
	return PWHashStr{C.GoString(&s[0])}
}

//PWHashVerify verifies password.
func (s PWHashStr) PWHashVerify(pw string) (err error) {
	if int(C.crypto_pwhash_str_verify(
		C.CString(s.string),
		C.CString(pw),
		(C.ulonglong)(len(pw)))) != 0 {
		err = ErrPassword
	}
	return
}

// Value returns the string value of the PWHashStr.
func (s PWHashStr) Value() string {
	return s.string
}
