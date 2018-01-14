package sodium

import "fmt"

//
// Internal support functions
//

// CheckTypedSize verifies the expected size of a Typed byte array.
func checkTypedSize(typed Typed, descrip string) {
	switch typed.(type) {
	case *GenericHashKey:
		got := typed.Length()
		min, max := cryptoGenericHashBytesMin, cryptoGenericHashBytesMax
		checkSizeInRange(got, min, max, descrip)
	case *SubKey:
		got := typed.Length()
		min, max := CryptoKDFBytesMin, CryptoKDFBytesMax
		checkSizeInRange(got, min, max, descrip)
	default:
		expected := typed.Size()
		got := typed.Length()
		if got != expected {
			panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d), got (%d).\n", descrip, expected, got))
		}
	}
}

func checkSizeInRange(size int, min int, max int, descrip string) {
	if size < min || size > max {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d - %d), got (%d).", descrip, min, max, size))
	}
}
