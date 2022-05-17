package main

import (
	"flag"
	"log"
	"time"

	"github.com/UzL-ITS/sev-step/sevStep"
)

func main() {
	cpu := flag.Int("cpu", -1, "")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")

	flag.Parse()

	if *cpu == -1 {
		log.Fatalf("Set cpu")
	}

	ioctlAPI, err := sevStep.NewIoctlAPI("/dev/kvm", *getRIP)
	if err != nil {
		log.Fatalf("Failed to init ioctl API : %v", err)
	}
	defer ioctlAPI.Close()

	if err := ioctlAPI.CmdSetupRetInstrPerf(*cpu); err != nil {
		log.Printf("Failed to setup perf : %v", err)
		return
	}

	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		reading, err := ioctlAPI.CmdReadRetInstrPerf(*cpu)
		if err != nil {
			log.Printf("Failed to read perf counter : %v\n", err)
			return
		}
		log.Printf("Counter reading %v\n", reading)
	}

}
