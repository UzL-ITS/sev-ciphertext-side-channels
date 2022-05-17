package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"pfFingerprint"

	"github.com/UzL-ITS/sev-step/sevStep"
)

func main() {
	gpa1 := flag.Uint64("gpa1", 0, "first gpa for toggle tracking")
	gpa2 := flag.Uint64("gpa2", 0, "second gpa for toggle tracking")
	trackingTypeParam := flag.String("tracking", "execute", "values: {access,execute}. Determines tracking type")
	writeTrackInbetween := flag.Bool("writeTrackInbetween", false, "Write track all pages between exec track toggle")
	out := flag.String("out", "pf-log.txt", "output file")
	ignoreCycles := flag.Int("ignoreCycles", 3, "Amount of cycles at start to ignore for write addr finding")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")

	flag.Parse()

	if *gpa1 == 0 || *gpa2 == 0 {
		log.Printf("Please set gpa1 and gpa2")
		return
	}

	if *out == "" {
		log.Printf("Pleaset set \"-out\"")
		return
	}

	outFile, err := os.Create(*out)
	if err != nil {
		log.Fatalf("Failed  to create output file : %v\n", err)
	}
	defer outFile.Close()
	outWriter := bufio.NewWriter(outFile)
	defer outWriter.Flush()

	var trackingType sevStep.PageTrackMode
	if *trackingTypeParam == "access" {
		trackingType = sevStep.PageTrackAccess
	} else if *trackingTypeParam == "execute" {
		trackingType = sevStep.PageTrackExec
	} else {
		log.Printf("Please set valid value for \"tracking\" param\n")
		flag.PrintDefaults()
		return
	}

	ioctlAPI, err := sevStep.NewIoctlAPI("/dev/kvm", *getRIP)
	if err != nil {
		log.Fatalf("Failed to init ioctl API : %v", err)
	}
	defer ioctlAPI.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("Tracking start page 0x%016x\n", *gpa1)
	if err := ioctlAPI.CmdTrackPage(*gpa1, trackingType); err != nil {
		log.Printf("failed to track %x : %v", *gpa1, err)
		return
	}

	gpa1CycleCount := 0
	inCycle := false
	cycleLog := make([]uint64, 0)
	for {
		ev, err := pfFingerprint.WaitForEventBlocking(ctx, ioctlAPI)
		if err != nil {
			log.Printf("WaitForEventBlocking failed : %v", err)
			return
		}

		//log.Printf("%s\n", ev)
		errCodes, err := sevStep.ErrorCodeToString(ev.ErrorCode)
		if err != nil {
			log.Printf("failed to generate errror codes :%v", err)
			errCodes = "<error>"
		}
		if _, err := outWriter.WriteString(fmt.Sprintf("%s %s\n", ev, errCodes)); err != nil {
			log.Printf("write to output file failed : %v", err)
		}

		switch ev.FaultedGPA {
		case *gpa1:
			if *writeTrackInbetween && gpa1CycleCount == *ignoreCycles+1 {
				log.Printf("Write GPA is %x", cycleLog[len(cycleLog)-1])

				cycleLog = cycleLog[:0]
				inCycle = false
			}
			//log.Printf("Exec at gpa1")
			if err := ioctlAPI.CmdTrackPage(*gpa2, trackingType); err != nil {
				log.Printf("Failed to track gpa %x : %v", *gpa2, err)
				return
			}
			if *writeTrackInbetween && gpa1CycleCount == *ignoreCycles {
				if err := ioctlAPI.CmdTrackAllPages(sevStep.PageTrackAccess); err != nil {
					log.Printf("Failed to write track all : %v", err)
					return
				}
				inCycle = true
			}
			gpa1CycleCount++
		case *gpa2:
			//log.Printf("Exec at gpa2")
			if err := ioctlAPI.CmdTrackPage(*gpa1, trackingType); err != nil {
				log.Printf("Failed to track gpa %x : %v", *gpa1, err)
				return
			}
		default:
			if *writeTrackInbetween && inCycle {
				cycleLog = append(cycleLog, ev.FaultedGPA)
			}
		}

		if err := ioctlAPI.CmdAckEvent(ev.ID); err != nil {
			log.Printf("Failed to ack event %v : %v", ev, err)
			return
		}

	}

}
