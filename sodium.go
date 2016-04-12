package sodium

import "errors"

var (
	ErrAuth = errors.New("sodium: Message forged.")
	ErrOpenBox = errors.New("sodium: Can't open box.")
	ErrOpenSign = errors.New("sodium: Signature forged.")
	ErrDecryptAEAD = errors.New("sodium: Can't decrypt message.")
)
