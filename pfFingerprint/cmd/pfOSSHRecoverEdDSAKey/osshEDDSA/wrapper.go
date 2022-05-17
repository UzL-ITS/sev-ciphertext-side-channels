//osshEDDSA is a Go wrapper for to the C edDSA implementation from OpenSSH that allows to recover
// H_{0...b}(sk) from b

package osshEDDSA

//#include "ge25519.h"
import "C"
import "unsafe"

func RecoverBigRFromB(recoveredB []int8) []byte {

	secret := make([]byte, 32)
	buf := make([]byte, len(recoveredB))
	for i, v := range recoveredB {
		buf[i] = byte(v)
	}

	var cPtrSecret *C.uint8_t
	var cPtrB *C.int8_t
	cPtrB = (*C.int8_t)(C.CBytes(buf))
	cPtrSecret = (*C.uint8_t)(C.CBytes(secret))

	C.compute_r_from_sc_info(cPtrB, cPtrSecret)
	secret = C.GoBytes(unsafe.Pointer(cPtrSecret), C.int(len(secret)))
	return secret
}
