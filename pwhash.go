package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "unsafe"

var (
	cryptoPWHashSaltBytes           = int(C.crypto_pwhash_saltbytes())
	cryptoPWHashStrBytes            = int(C.crypto_pwhash_strbytes())
	CryptoPWHashOpsLimitInteractive = int(C.crypto_pwhash_opslimit_interactive())
	CryptoPWHashMemLimitInteractive = int(C.crypto_pwhash_memlimit_interactive())
	CryptoPWHashOpsLimitModerate    = int(C.crypto_pwhash_opslimit_moderate())
	CryptoPWHashMemLimitModerate    = int(C.crypto_pwhash_memlimit_moderate())
	CryptoPWHashOpsLimitSensitive   = int(C.crypto_pwhash_opslimit_sensitive())
	CryptoPWHashMemLimitSensitive   = int(C.crypto_pwhash_memlimit_sensitive())
)

// PWHashSalt implements the Typed interface
type PWHashSalt struct {
	Bytes
}

func (s PWHashSalt) Size() int {
	return cryptoPWHashSaltBytes
}

// PWHashStr implements the Typed interface
type PWHashStr struct {
	string
}

func LoadPWHashStr(b Bytes) PWHashStr {
	t := new(PWHashStr)
	t.setBytes(b)
	return *t
}

// Value returns the underlying bytes for PWHashStr
func (s PWHashStr) Value() Bytes {
	return Bytes(s.string)
}

func (s PWHashStr) Size() int {
	return cryptoPWHashStrBytes
}

func (s PWHashStr) Length() int {
	return len(s.string)
}

func (s *PWHashStr) setBytes(b Bytes) {
	t := PWHashStr{string(b[:])}
	checkTypedSize(&t, "PWHashStr")
	*s = t
}

//PWHashStore use moderate profile to pack hashed password into PWHashStr.
func PWHashStore(pw string) PWHashStr {
	s := make([]C.char, cryptoPWHashStrBytes)
	pwc := C.CString(pw)
	defer C.free(unsafe.Pointer(pwc))

	if int(C.crypto_pwhash_str(
		&s[0],
		pwc,
		(C.ulonglong)(len(pw)),
		(C.ulonglong)(CryptoPWHashOpsLimitModerate),
		(C.size_t)(CryptoPWHashMemLimitModerate))) != 0 {
		panic("see libsodium")
	}
	return PWHashStr{C.GoStringN(&s[0], C.int(cryptoPWHashStrBytes))}
}

//PWHashStoreSensitive use sensitive profile to pack hashed password into PWHashStr.
func PWHashStoreSensitive(pw string) PWHashStr {
	s := make([]C.char, cryptoPWHashStrBytes)
	pwc := C.CString(pw)
	defer C.free(unsafe.Pointer(pwc))

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

//PWHashStoreInteractive use interactive profile to pack hashed password into PWHashStr.
func PWHashStoreInteractive(pw string) PWHashStr {
	s := make([]C.char, cryptoPWHashStrBytes)
	pwc := C.CString(pw)
	defer C.free(unsafe.Pointer(pwc))

	if int(C.crypto_pwhash_str(
		&s[0],
		pwc,
		(C.ulonglong)(len(pw)),
		(C.ulonglong)(CryptoPWHashOpsLimitInteractive),
		(C.size_t)(CryptoPWHashMemLimitInteractive))) != 0 {
		panic("see libsodium")
	}
	return PWHashStr{C.GoString(&s[0])}
}

//PWHashVerify verifies password.
func (s PWHashStr) PWHashVerify(pw string) (err error) {
	sc := C.CString(s.string)
	defer C.free(unsafe.Pointer(sc))
	pwc := C.CString(pw)
	defer C.free(unsafe.Pointer(pwc))
	if int(C.crypto_pwhash_str_verify(
		sc,
		pwc,
		(C.ulonglong)(len(pw)))) != 0 {
		err = ErrPassword
	}
	return
}
