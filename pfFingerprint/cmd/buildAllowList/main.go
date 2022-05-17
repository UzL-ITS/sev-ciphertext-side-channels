//Takes traces of pages accesses during target execution and returns the set of addresses contained in
//all execution. Useful to limit the amount tracked pages in attack code, reducing the noise.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/UzL-ITS/sev-step/sevStep"
	"io"
	"log"
	"os"
	"strings"
)

func ParseInputFileWithRuns(r io.Reader) ([][]*sevStep.Event, error) {
	sc := bufio.NewScanner(r)
	sc.Split(bufio.ScanLines)

	eventsByRuns := make([][]*sevStep.Event, 0)
	eventsSingleRun := make([]*sevStep.Event, 0)
	printedWarningNonJSON := false
	printedWarningNoRIP := false

	insideTrace := false

	for sc.Scan() {
		line := strings.TrimLeft(sc.Text(), " ")

		if strings.HasPrefix(line, "Start") {
			if insideTrace {
				log.Printf("Encountered \"Start\" while inside trace, this should not happen!")
			}
			insideTrace = true
		}

		if !insideTrace {
			continue
		}

		if strings.HasPrefix(line, "Stop") {
			eventsByRuns = append(eventsByRuns, eventsSingleRun)
			eventsSingleRun = make([]*sevStep.Event, 0)
			insideTrace = false
			continue
		}

		if !strings.HasPrefix(line, "{") {
			if !printedWarningNonJSON {
				log.Printf("omiting non json lines")
			}
			printedWarningNonJSON = true
			continue
		}

		v, err := sevStep.ParseEventFromJSON(line)
		if err != nil {
			return nil, fmt.Errorf("ParseEventFromJSON failed on %s : %v", line, err)
		}

		if !v.HaveRipInfo && !printedWarningNoRIP {
			log.Printf("Some entries do not have RIP info")
			printedWarningNoRIP = true
		}

		eventsSingleRun = append(eventsSingleRun, v)

	}
	if sc.Err() != nil {
		return nil, fmt.Errorf("scanner error : %v", sc.Err())
	}
	return eventsByRuns, nil
}

func intersectRunSets(runs []map[uint64]bool) map[uint64]bool {
	intersection := make(map[uint64]bool)

	if len(runs) == 0 {
		return intersection
	}

	//init
	for k := range runs[0] {
		intersection[k] = true
	}

	//merge
	for i := 1; i < len(runs); i++ {
		//check for each elem in intersection if they are in the next run as well
		for k, v := range intersection {
			//if elem is not in next run, remove from intersection
			if v && !runs[i][k] {
				intersection[k] = false
			}
		}
	}

	return intersection
}

func main() {
	in := flag.String("in", "", "input file")
	out := flag.String("out", "intersect-set.txt", "output file name")
	excludeKernel := flag.Bool("excludeKernel", false, "Exclude kernel space rips")

	flag.Parse()

	if *in == "" {
		log.Fatalf("set in\n")
	}

	inFile, err := os.Open(*in)
	if err != nil {
		log.Fatalf("Failed to open input file : %v", err)
	}
	defer inFile.Close()

	eventsByRun, err := ParseInputFileWithRuns(inFile)
	if err != nil {
		log.Fatalf("Failed to parse input file")
	}

	//create sets for runs
	runSets := make([]map[uint64]bool, len(eventsByRun))
	for runIDX, eventsInRun := range eventsByRun {
		runSets[runIDX] = make(map[uint64]bool)
		for _, v := range eventsInRun {
			if *excludeKernel && v.RIP >= 0xffff800000000000 {
				continue
			}
			runSets[runIDX][v.FaultedGPA] = true
		}

	}

	intersection := intersectRunSets(runSets)

	outFile, err := os.Create(*out)
	if err != nil {
		log.Fatalf("Failed to create outfile : %v", err)
	}
	defer outFile.Close()

	count := 0
	for k, v := range intersection {
		if v {
			count++
			if _, err := outFile.WriteString(fmt.Sprintf("0x%x\n", k)); err != nil {
				log.Fatalf("Failed to write to out file :%v", err)
			}
		}
	}
	log.Printf("Intersection has %v elements\n", count)

}
