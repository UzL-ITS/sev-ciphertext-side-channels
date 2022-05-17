//Test utility to check that toggling between exec and write tracking works as expected
package main

import (
	"context"
	"flag"
	"github.com/UzL-ITS/sev-step/sevStep"
	"log"
	"os"
	"os/signal"
	"pfFingerprint"
)

func main() {
	exec1 := flag.Uint64("exec1", 0, "first exec gpa for  tracking")
	exec2 := flag.Uint64("exec2", 0, "second exec gpa for tracking tracking")
	write1 := flag.Uint64("write1", 0, "first write gpa for tracking")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")

	flag.Parse()

	if *exec1 == 0 || *exec2 == 0 || *write1 == 0 {
		log.Printf("Please set exec1, exec2 and write1")
		return
	}

	ioctlAPI, err := sevStep.NewIoctlAPI("/dev/kvm", *getRIP)
	if err != nil {
		log.Fatalf("Failed to init ioctl API : %v", err)
	}
	defer ioctlAPI.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("Tracking start page 0x%016x\n", *exec1)
	if err := ioctlAPI.CmdTrackPage(*exec1, sevStep.PageTrackAccess); err != nil {
		log.Printf("failed to track %x : %v", *exec1, err)
		return
	}

	for {
		ev, err := pfFingerprint.WaitForEventBlocking(ctx, ioctlAPI)
		if err != nil {
			log.Printf("WaitForEventBlocking failed : %v", err)
			return
		}

		errCodes, err := sevStep.ErrorCodeToString(ev.ErrorCode)
		if err != nil {
			log.Printf("Failed to get name for error codes")
			errCodes = "<error>"
		}
		//log.Printf("%s ErrCodes = (%s)\n", ev, errCodes)

		switch ev.FaultedGPA {
		case *exec1:
			log.Printf("Exec at exec1 (%s), tracking write1\n", errCodes)
			if err := ioctlAPI.CmdTrackPage(*write1, sevStep.PageTrackAccess); err != nil {
				log.Printf("Failed to track gpa %x : %v", *exec2, err)
				return
			}
			if err := ioctlAPI.CmdTrackPage(*write1, sevStep.PageTrackAccess); err != nil {
				log.Printf("Failed to track gpa %x : %v", *exec2, err)
				return
			}
		case *write1:
			log.Printf("Write at write1 (%s) tracking exec2\n", errCodes)
			if err := ioctlAPI.CmdTrackPage(*exec2, sevStep.PageTrackAccess); err != nil {
				log.Printf("Failed to track gpa %x : %v", *exec2, err)
				return
			}
		case *exec2:
			log.Printf("Exec at exec2 (%s), tracking exec1\n", errCodes)
			if err := ioctlAPI.CmdTrackPage(*exec1, sevStep.PageTrackAccess); err != nil {
				log.Printf("Failed to track gpa %x : %v", *exec1, err)
				return
			}
		default:
			log.Printf("Unexpted page fault at : %v\n", ev)
		}

		if err := ioctlAPI.CmdAckEvent(ev.ID); err != nil {
			log.Printf("Failed to ack event %v : %v", ev, err)
			return
		}

	}

}
