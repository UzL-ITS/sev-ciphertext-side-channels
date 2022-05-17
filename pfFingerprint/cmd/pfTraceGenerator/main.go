//Triggers the ecdh dummy server and records page faults  until the server replies. Has many options to configure recording
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"pfFingerprint/trigger"
	"strconv"
	"strings"

	"github.com/UzL-ITS/sev-step/sevStep"

	"log"
	"os"
	"os/signal"
	"pfFingerprint"
	"sync"
	"time"
)

//initTracking if allowList != nil only the gpas in the list are tracked, otherwise all pages are tracked
func initTracking(ioctlAPI *sevStep.IoctlAPI, allowList []uint64, trackType sevStep.PageTrackMode, findWrite bool) error {
	if allowList == nil {
		if findWrite {
			log.Printf("Doing additional write track")
			if err := ioctlAPI.CmdTrackAllPages(sevStep.PageTrackWrite); err != nil {
				return fmt.Errorf("CmdTrackAllPages write failed : %v", err)
			}
		}

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

func isWriteErr(code uint32) bool {
	return code == 0x7
}

func main() {

	triggerURI := flag.String("triggerURI", "http://localhost:8080", "Either http://someAddress:port or ssh://someHost:port")
	out := flag.String("out", "pf-log.txt", "path to write page fault events to")
	trackingTypeParam := flag.String("tracking", "access", "values: {access,execute}. Determines tracking type")
	format := flag.String("format", "plain", "{plain,json}, format event output")
	retrack := flag.Bool("retrack", true, "re-track pages")
	allowListPath := flag.String("allowList", "", "only track pages from this list")
	iterations := flag.Uint("iterations", 0, "Iterations for tracking If set to 0 iterations are starting by pressing enter")
	findWrite := flag.Bool("findWrite", false, "also do write tracking to find buffer location")
	simExcludeKernelSpace := flag.Bool("simExcludeKernelSpace", false, "Simulate Kernel space exclusion by filtering based on RIP")
	cpu := flag.Int("cpu", -1, "Test parameter for perf readings. If set, guest must be pinned to this virtual cpu")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")

	flag.Parse()

	victimTrigger, err := trigger.NewTriggerFromURI(*triggerURI)
	if err != nil {
		log.Printf("Failed to parse triggerURI :%v", err)
		return
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

	outFile, err := os.Create(*out)
	if err != nil {
		log.Printf("Failed to open outFile : %v", err)
		return
	}
	defer outFile.Close()
	outWriter := bufio.NewWriterSize(outFile, 51200000000)
	defer outWriter.Flush()
	outWriterLock := sync.Mutex{}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("getRIP? %v\n", *getRIP)
	ioctlAPI, err := sevStep.NewIoctlAPI("/dev/kvm", *getRIP)
	if err != nil {
		log.Fatalf("Failed to init ioctl API : %v", err)
	}
	defer ioctlAPI.Close()

	if *cpu != -1 {
		if err := ioctlAPI.CmdSetupRetInstrPerf(*cpu); err != nil {
			log.Printf("Failed to setup perf counters on cpu %v : %v", *cpu, err)
			return
		}
	}

	eventChan := pfFingerprint.OpenEventChannel(ctx, ioctlAPI)
	wg := sync.WaitGroup{}

	retrackBacklog := make([]*sevStep.Event, 0)

	//print events
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		eventCounter := 0
		defer func() {
			log.Printf("Processed %v events\n", eventCounter)
		}()
		var lastRetiredInstrReading uint64
		var retiredInstrSinceLastFault float64
		if *cpu != -1 {
			lastRetiredInstrReading, err = ioctlAPI.CmdReadRetInstrPerf(*cpu)
			if err != nil {
				log.Printf("Failed to read retired instructions perf on cpu %v : %v", cpu, err)
				return
			}
			log.Printf("Initial retired instruction reading is %v\n", lastRetiredInstrReading)

		}
		for {
			select {
			case <-ctx.Done():
				log.Printf("Main loop got abort signal, shutting down")
				return
			case e, ok := <-eventChan:
				if !ok {
					log.Printf("Event channel closed, shutting down")
					return
				}
				eventCounter++

				//update retiredInstrSinceLastFault if scheduled to single cpu
				if *cpu != -1 {
					currentRetiredInstrReading, err := ioctlAPI.CmdReadRetInstrPerf(*cpu)
					if err != nil {
						log.Printf("Failed to read retired instructions perf on cpu %v : %v\n", cpu, err)
						return
					}
					retiredInstrSinceLastFault = math.Abs(float64(currentRetiredInstrReading - lastRetiredInstrReading))
					lastRetiredInstrReading = currentRetiredInstrReading
				}
				var data []byte
				if *format == "json" {
					data, err = json.Marshal(e)
					if err != nil {
						log.Printf("Failed to marshal event to json")
						return
					}
					data = append(data, []byte("\n")...) //add new line
				} else if *format == "plain" {
					pfErrAsString, err := sevStep.ErrorCodeToString(e.ErrorCode)
					if err != nil {
						log.Printf("failed to convert pf err code to string : %v", err)
						pfErrAsString = "<error>"
					}
					retInstStr := "Not available"
					if *cpu != -1 {
						retInstStr = fmt.Sprintf("%v", retiredInstrSinceLastFault)
					}
					data = []byte(fmt.Sprintf("%s Error Bits(%s) RetInstrDelta %v\n", e.String(), pfErrAsString, retInstStr))
				}

				outWriterLock.Lock()
				if _, err := outWriter.Write(data); err != nil {
					log.Printf("Failed to write event to file : %v", err)
					outWriterLock.Unlock()
					return
				}
				outWriterLock.Unlock()

				//re-track logic

				//hack: to exclude kernel space in test filter out
				// e.RIP < 0xffff800000000000

				if *retrack && (!(*simExcludeKernelSpace) || e.RIP < 0xffff800000000000) {
					outWriterLock.Lock()
					if len(retrackBacklog) > 0 {

						var progressSinceLastFault bool
						if !(*getRIP) {

							progressSinceLastFault = retiredInstrSinceLastFault > 2
							//log.Printf("Retired instructions since last fault : %v", retiredInstrSinceLastFaul)
						} else {
							//lastElem := retrackBacklog[len(retrackBacklog)-1]
							progressSinceLastFault = true //lastElem.RIP != e.RIP
						}

						//if true, re-track elements and clear backlog, RIP chain broken
						if progressSinceLastFault {
							//log.Printf("Retracking %v elems in total\n", len(retrackBacklog))
							for _, v := range retrackBacklog {
								//log.Printf("Retracking %v\n",v)

								//retrack write faults as write, everything else as default trackType
								retrackType := trackType
								if *findWrite && isWriteErr(v.ErrorCode) {
									log.Printf("Retracking 0x%x as write\n", v.FaultedGPA)
									retrackType = sevStep.PageTrackWrite
								}
								if err := ioctlAPI.CmdTrackPage(v.FaultedGPA, retrackType); err != nil {
									log.Printf("Failed to retrack %x :%vn", v, err)
									outWriterLock.Unlock()
									return
								}
							}
							retrackBacklog = retrackBacklog[:0]
						}
					}
					retrackBacklog = append(retrackBacklog, e)
					outWriterLock.Unlock()

				}

				if err := ioctlAPI.CmdAckEvent(e.ID); err != nil {
					log.Printf("Failed to ack event %v\n", e.ID)
					return
				}

			}
		}
	}()

	//trigger victim and tracking
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		var haveNextRound func() bool
		abort := false

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

		for haveNextRound() {
			//check if context has been canceled in the meantime
			select {
			case <-ctx.Done():
				abort = true
				continue
			default:
			}

			//write measurement start header to log file
			outWriterLock.Lock()
			if _, err := outWriter.WriteString(fmt.Sprintf("Start %v\n", time.Now().Format(time.StampNano))); err != nil {
				log.Printf("Failed to write start of ecdh event : %v", err)
				outWriterLock.Unlock()
				return
			}
			outWriterLock.Unlock()

			outWriterLock.Lock()
			retrackBacklog = retrackBacklog[:0]
			outWriterLock.Unlock()

			log.Printf("Initialize tracking\n")
			if err := initTracking(ioctlAPI, allowList, trackType, *findWrite); err != nil {
				log.Printf("initTracking failed : %v", err)
				return
			}

			log.Printf("Triggering Victim")
			if _, err := victimTrigger.Execute(); err != nil {
				log.Printf("Failed to execute victim trigger : %v", err)
				return
			}
			log.Printf("Victim done\n")

			//write measurement done trailer to log file
			outWriterLock.Lock()
			if _, err := outWriter.WriteString(fmt.Sprintf("Stop %v\n", time.Now().Format(time.StampNano))); err != nil {
				log.Printf("Failed to write start of ecdh event : %v", err)
				outWriterLock.Unlock()
				return
			}
			outWriterLock.Unlock()

			if err := ioctlAPI.CmdUnTrackAllPages(trackType); err != nil {
				log.Printf("CmdUnTrackAllPages failed : %v", err)
				return
			}
			if *findWrite {
				if err := ioctlAPI.CmdUnTrackAllPages(sevStep.PageTrackWrite); err != nil {
					log.Printf("CmdUnTrackAllPages write failed : %v", err)
					return
				}
			}

		}
	}()

	wg.Wait()

}
