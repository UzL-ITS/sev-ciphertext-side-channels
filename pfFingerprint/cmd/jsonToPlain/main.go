package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/UzL-ITS/sev-step/sevStep"
)

func main() {
	in := flag.String("in", "pf-log.txt", "Input file with json strings")
	out := flag.String("out", "plain-pf-log.txt", "Output file with plaintext and hex number")

	flag.Parse()

	if *in == "" || *out == "" {
		log.Printf("Specify \"-in\" and \"-out\"")
		return
	}

	inFile, err := os.Open(*in)
	if err != nil {
		log.Printf("failed to load open %v :%v", *in, err)
		return
	}
	defer inFile.Close()
	inReader := bufio.NewReader(inFile)

	outFile, err := os.Create(*out)
	if err != nil {
		log.Printf("Failed to create outfile %v : %v", *out, err)
		return
	}
	defer outFile.Close()
	outWriter := bufio.NewWriter(outFile)
	defer outWriter.Flush()

	events, err := sevStep.ParseInputFile(inReader)
	if err != nil {
		log.Printf("Failed to parse input file %v\n", err)
		return
	}

	for _, v := range events {
		if _, err := outWriter.WriteString(fmt.Sprintf("%v\n", v)); err != nil {
			log.Printf("Failed to write to out file %v\n", err)
			return
		}
	}

}
