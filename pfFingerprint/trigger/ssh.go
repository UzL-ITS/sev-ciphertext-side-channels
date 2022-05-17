package trigger

//Construct Triggerer for ssh URIs

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/ed25519"

	"golang.org/x/crypto/ssh"
)

type SSHTrigger struct {
	config              *ssh.ClientConfig
	addr                string
	marshalledPublicKey []byte
}

type SSHSignatureMessage struct {
	SignatureType string
	Signature     []byte
	Message       []byte
	PublicKeySSH  []byte
}

func (s *SSHTrigger) Execute() ([]byte, error) {
	client, err := ssh.Dial("tcp", s.addr, s.config)

	sigMsg := SSHSignatureMessage{
		ssh.LastSignature.Format,
		ssh.LastSignature.Blob,
		ssh.LastMessage,
		s.marshalledPublicKey,
	}
	buf := &bytes.Buffer{}
	if err := gob.NewEncoder(buf).Encode(sigMsg); err != nil {
		return nil, fmt.Errorf("failed to encode signature data : %v", err)
	}

	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return buf.Bytes(), nil
		}
		return nil, fmt.Errorf("failed to dial : %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("SSHTrigger failed to close client :%v", err)
		}
	}()

	return buf.Bytes(), nil
}

func NewSSHTrigger(user, addr string) Triggerer {
	/*
			//we could use this to actually connect via unlocked key in agent
			//however, for receiving the signature that we want, we do not
		    //need to present valid credentials
			socket := os.Getenv("SSH_AUTH_SOCK")
			conn, err := net.Dial("unix", socket)
			if err != nil {
				return nil, fmt.Errorf("failed to open SSH_AUTH_SOCK")
			}
			agentClient := agent.NewClient(conn)
	*/

	sshTrigger := &SSHTrigger{
		addr: addr,
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password("i will not pass"),
			//ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if key.Type() != ssh.KeyAlgoED25519 {
				return fmt.Errorf("SSH server did not send ed25519 signature")
			}
			cryptPubKey, ok := key.(ssh.CryptoPublicKey)
			if !ok {
				return fmt.Errorf("key did not implement ssh.CryptoPublicKey, cannot get raw key")
			}
			edPubKey, ok := cryptPubKey.CryptoPublicKey().(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("failed to cast to ed25519.PublicKey")
			}
			sshTrigger.marshalledPublicKey = edPubKey

			return nil
		},
		HostKeyAlgorithms: []string{"ssh-ed25519"},
	}
	sshTrigger.config = config

	return sshTrigger
}
