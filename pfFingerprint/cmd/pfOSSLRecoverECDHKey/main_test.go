package main

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func Test_parseSecretFromOpensslLog2(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Short 1",
			args: args{r: strings.NewReader("secretFromOpenSSL f0")},
			want: []byte{0, 0, 0, 0, 1, 1, 1, 1},
		},
		{
			name: "Short 2",
			args: args{r: strings.NewReader("secretFromOpenSSL 81:82")},
			want: []byte{1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "Long",
			args: args{r: strings.NewReader(`secretFromOpenSSL F8:FF:2D:BF:0D:D0:DB:08:50:2F:87:99:6C:4B:00:FE:57:57:9F:EB:79:B2:B0:C2:77:E9:8B:13:56:FB:F7:4C`)},
			want: []byte{0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSecretFromOpensslLog2(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSecretFromOpensslLog2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSecretFromOpensslLog2() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Swaphistory_To_Secret(t *testing.T) {
	//
	// setup
	//
	correctSecret, err := parseSecretFromOpensslLog2(strings.NewReader(`secretFromOpenSSL F8:FF:2D:BF:0D:D0:DB:08:50:2F:87:99:6C:4B:00:FE:57:57:9F:EB:79:B2:B0:C2:77:E9:8B:13:56:FB:F7:4C`))
	if err != nil {
		t.Errorf("Failed to parse openssl secret : %v", err)
	}

	rawSwap := `0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 1 1 1 0 1 0 0 0 0 0 1 1 0 1 1 0 1 0 0 0 0 0 0 0 1 1 1 0 0 0 1 1 0 1 1 0 1 0 0 1 1 0 0 0 0 0 0 0 1 1 1 1 1 0 0 0 1 1 1 0 1 0 0 1 0 0 0 1 0 1 0 1 0 1 0 1 1 0 1 0 1 1 0 1 1 0 1 1 1 0 1 1 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 0 0 1 1 1 1 1 1 0 0 0 0 1 0 1 0 0 1 1 1 1 0 0 0 1 0 1 0 0 0 1 0 1 1 0 1 0 1 1 1 0 0 0 1 0 1 1 1 1 1 0 0 0 1 0 0 0 0 1 1 0 0 1 1 1 0 1 1 1 0 0 0 0 1 1 1 0 0 1 0 0 1 0 1 1 0 0 0 1 0 1 1 1 1 1 1 0 1 1 0 0 0 0 0 0 0 1 1 0 0 0 1 0 1 0 1 0 1 1`
	tokens := strings.Split(rawSwap, " ")
	lowToHighSwap := make([]byte, len(tokens))
	for i, v := range tokens {
		switch v {
		case "0":
			lowToHighSwap[i] = 0
		case "1":
			lowToHighSwap[i] = 1
		default:
			t.Errorf("rawSap has unexpected value \"%v\"\n", v)
		}
	}

	//
	//recover secret
	//

	recoveredScalar, err := recoverScalarFromX25519Swaps(lowToHighSwap)
	if err != nil {
		t.Fatalf("Unexpected error in keyRecoveryX25519ScalarMulx : %v\n", err)
	}
	correctScalar, err := x25519KeyToScalar(correctSecret)
	if err != nil {
		t.Fatalf("Unexpected error in x25519KeyToScalar : %v\n", err)
	}

	for i := range correctScalar {
		if recoveredScalar[i] != correctScalar[i] {
			t.Errorf("Missmatch at pos %v, want %v got %v\n", i, correctSecret[i], recoveredScalar[i])
		}
	}

}
