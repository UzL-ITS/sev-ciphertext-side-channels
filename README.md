This repo contains the code to reproduce the experiments
for the "A Systematic Look at Ciphertext Side Channels on AMD SEV-SNP"
research paper.

# Secure Context Switch
The patch file `poc-secure-context-switch.patch` contains our POC implementation for
secure context switches, as described in the paper.
The patch is against the AMD Linux Kernel Repo
https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel branch `sev-snp-part2-rfc4` at commit `c1f51e5d9156252cb296630323a7a5608c20edfd`

To allow convenient testing/evaluation, the patch is only activated for programs containing `CONSTANT_CHANGE=1` in their
environment (e.g. use `CONSTANT_CHANGE=1 ./myprog` to start your program with the mitigations applied)


# Attack Framework
The basic attack framework can be found at https://github.com/UzL-ITS/sev-step .
It is built as a kernel patch that introduces a userspace API to perform controlled channel
attacks.

# EdDSA Attack
The folder `pfFingerprint` contains the attack against the EdDSA implementation in OpenSSH.
It uses the attack framework from https://github.com/UzL-ITS/sev-step.
It also contains several helper binaries showcasing the functionality of the framework.

## Setup & Execution
1) Perform the setup in https://github.com/UzL-ITS/sev-step to install the framework and setup
a SEV VM
2) Install https://github.com/zegelin/qemu-affinity on the host
3) Add the following Qemu cli options when starting the VM
 - Add `-name <vm name>,debug-threads=on` to enable to pin the vCPU to a fixed core later on
 - Make sure to forward port `2223` to localhost, .e.g. with
 ```
 -netdev user,id=vmnic,hostfwd=tcp:127.0.0.1:2223-:2223
 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile=
 ```
4) Copy the `openssh-target` folder to the VM. Edit the three `HostKey ...` entries in `openssh-target/victim-sshd-config/sshd_config` to contain the absolute path for the key files (w.r.t to the location in the VM)
5) Inside the VM, start the victim sshd process with `<full path to victim-sshd> -p2223 -f <full path to sshd_config>`
6) Build the attack tools in `pfFingerprint` using `make`.
7) cd to `pfFingerprint/pfFingerprint-attack-scripts/openssh/` and execute `sudo ./attack-sequence.sh --no-rip --cpu <cpu>` where `<cpu>` (is the logical cpu core to pin the VM to) to perform the attack.

## Reuseable tools
While most of the code is quite specific to the EdDSA attack
some tools can be reused.

First of all, the attack framework in https://github.com/UzL-ITS/sev-step is completely untangled from this attack and simply
provides an ioctl API (and a go wrapper around it) to
track page accesses either in batch or interactively.

The tools `pfBatchTraceGenerator` and `pfTraceGenerator` in `pfFingerprint/cmd` can
easily be used as a building block for your own experiments.
They are also a good example of using the API.
Both tools can trigger some functionality in the VM, either via http or ssh
and record page fault events from the start of the request until
the reply arrives.

