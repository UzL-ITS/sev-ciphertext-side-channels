module pfFingerprint

go 1.16

//this is required because i created a local copy of this package to extract aditional information
//from the ssh client
replace golang.org/x/crypto => /Users/luca/work/work-research/systematic-cipherleaks-sp22/rsa-sev-attack/pfFingerprint/ssh

require (
	filippo.io/edwards25519 v1.0.0-rc.1
	github.com/UzL-ITS/sev-step v0.4.2
	github.com/agnivade/levenshtein v1.1.1
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
)
