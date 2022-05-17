package pfFingerprint

import (
	"context"
	"errors"
	"fmt"
	"github.com/UzL-ITS/sev-step/sevStep"
	"log"
)

var ErrCtxCancelled = errors.New("context cancelled")

func OpenEventChannel(ctx context.Context, ioctlAPI *sevStep.IoctlAPI) <-chan *sevStep.Event {
	newEvents := make(chan *sevStep.Event)
	go func() {
		defer close(newEvents)
		for {
			select {
			case <-ctx.Done():
				log.Printf("openEventChannel, ctx canceled, returning")
				return
			default:
				e, ok, err := ioctlAPI.CmdPollEvent()
				if err != nil {
					log.Printf("Polling error %v", err)
					return
				}
				if ok {
					newEvents <- e
				}
			}
		}
	}()
	return newEvents
}

//WaitForEventBlocking blocks until next event is received or context is cancelled. Uses busy polling.
func WaitForEventBlocking(ctx context.Context, ioctlAPI *sevStep.IoctlAPI) (*sevStep.Event, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ErrCtxCancelled
		default:
			e, ok, err := ioctlAPI.CmdPollEvent()
			if err != nil {
				return nil, fmt.Errorf("CmdPollEvent failed : %v", err)
			}
			if ok {
				return e, nil
			}
		}
	}
}
