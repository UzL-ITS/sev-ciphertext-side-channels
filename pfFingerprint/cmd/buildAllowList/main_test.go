package main

import (
	"fmt"
	"github.com/UzL-ITS/sev-step/sevStep"
	"os"
	"testing"
)

func TestParseInputFileWithRuns(t *testing.T) {
	inFiles := []string{"../../single.txt", "../../pf-log-one.txt", "../../pf-log.txt"}
	for _, inPath := range inFiles {
		in, err := os.Open(inPath)
		if err != nil {
			t.Fatalf("Failed to open test input %v : %v", inPath, err)
		}
		defer in.Close()

		t.Run(fmt.Sprintf("Input file %s", inPath), func(t *testing.T) {
			got, err := ParseInputFileWithRuns(in)
			if err != nil {
				t.Fatalf("Unexpected error from ParseInputFileWithRuns: %v\n", err)
			}

			const wantInEachSet = 0x54411000
			for ii, vv := range got {
				found := false
				for _, v := range vv {
					if sevStep.OnSamePage(v.FaultedGPA, wantInEachSet) {
						found = true
					}
				}
				if !found {
					t.Errorf("Set %v (%v entries) does not contain 0x%x\n", ii, len(vv), wantInEachSet)
				}
			}
		})

	}

}
