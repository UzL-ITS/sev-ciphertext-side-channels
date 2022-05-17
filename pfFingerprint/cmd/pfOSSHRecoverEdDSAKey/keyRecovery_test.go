package main

import (
	"log"
	"reflect"
	"strings"
	"testing"
)

func TestParseOSSHKey(t *testing.T) {
	const in = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC7SW22Gk8/MZWVqU/BrrXXgEQ/mgCiOVPFxABoWTBE9wAAAJghfPAuIXzw
LgAAAAtzc2gtZWQyNTUxOQAAACC7SW22Gk8/MZWVqU/BrrXXgEQ/mgCiOVPFxABoWTBE9w
AAAEBwwsXw/2CKPusywklAzk45CPDZ9wc7ZJ0uT66ASNA4sbtJbbYaTz8xlZWpT8GutdeA
RD+aAKI5U8XEAGhZMET3AAAADnJvb3RAc2V2dmljdGltAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`

	_, err := parseOSSHKey(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Unexpected error : %v\n", err)
	}
}

func Test_signedBToUnsigned(t *testing.T) {
	type args struct {
		signed []int8
	}
	tests := []struct {
		name string
		args args
		want []int8
	}{
		{
			name: "Short",
			args: args{
				signed: []int8{-4, 01, -2, -4, 03, 03, -4, 02, 01, 02, 02, -1, 01, 02, 03, -1, -4, 00, -4, -4, 02, 00, -1},
			},
			want: []int8{04, 00, 06, 03, 02, 03, 04, 01, 01, 02, 02, 07, 00, 02, 03, 07, 03, 07, 03, 03, 01, 00, 07},
		},
		{
			name: "Full",
			args: args{
				signed: []int8{-4, 01, -2, -4, 03, 03, -4, 02, 01, 02, 02, -1, 01, 02, 03, -1, -4, 00, -4, -4, 02, 00, -1, -3, 02, -2, -4, -1, 00, 01, 00, -4, -4, -2, 01, 00, 03, -3, -2, 01, -4, 02, 03, -4, -3, 00, -3, -4, 01, -1, -1, 00, 03, 00, -4, -2, -1, -3, 02, 01, -4, 02, 01, 02, 02, 03, -3, 02, 02, 00, -2, 03, -3, -1, 02, -3, 00, 01, -3, -3, -2, 03, 03, -3, 01},
			},
			want: []int8{04, 00, 06, 03, 02, 03, 04, 01, 01, 02, 02, 07, 00, 02, 03, 07, 03, 07, 03, 03, 01, 00, 07, 04, 01, 06, 03, 06, 07, 00, 00, 04, 03, 05, 00, 00, 03, 05, 05, 00, 04, 01, 03, 04, 04, 07, 04, 03, 00, 07, 06, 07, 02, 00, 04, 05, 06, 04, 01, 01, 04, 01, 01, 02, 02, 03, 05, 01, 02, 00, 06, 02, 05, 06, 01, 05, 07, 00, 05, 04, 05, 02, 03, 05, 00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signedBToUnsigned(tt.args.signed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("signedBToUnsigned() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_unsignedBToSecret(t *testing.T) {
	type args struct {
		unsignedB []int8
	}
	tests := []struct {
		name string
		args args
		want [32]byte
	}{
		{
			name: "Test 1",
			args: args{
				unsignedB: []int8{04, 00, 06, 03, 02, 03, 04, 01, 01, 02, 02, 07, 00, 02, 03, 07, 03, 07, 03, 03, 01, 00, 07, 04, 01, 06, 03, 06, 07, 00, 00, 04, 03, 05, 00, 00, 03, 05, 05, 00, 04, 01, 03, 04, 04, 07, 04, 03, 00, 07, 06, 07, 02, 00, 04, 05, 06, 04, 01, 01, 04, 01, 01, 02, 02, 03, 05, 01, 02, 00, 06, 02, 05, 06, 01, 05, 07, 00, 05, 04, 05, 02, 03, 05, 00},
			},
			want: [32]byte{0x84, 0xa7, 0x31, 0x91, 0x0e, 0xed, 0xfb, 0x16, 0x9c, 0xf1, 0x7c, 0x80, 0x2b, 0xb0, 0x16, 0xcc, 0xc8, 0x73, 0xb8, 0x2f, 0xb0, 0x66, 0xc2, 0x44, 0x5a, 0x23, 0x58, 0x75, 0x7a, 0x94, 0xd5, 0x0a},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unsignedBToMessageDigestReduced(tt.args.unsignedB)
			if gotLen, wantLen := len(got), len(tt.want); gotLen != wantLen {
				t.Fatalf("length missmatch, got %v want %v", gotLen, wantLen)
			}
			for i := range tt.want {
				if tt.want[i] != got[i] {
					log.Printf("got  %02x", got)
					log.Printf("want %02x", tt.want)
					t.Errorf("Missmatch at idx %v, got %x want %x", i, got[i], tt.want[i])
				}
			}
		})
	}
}
