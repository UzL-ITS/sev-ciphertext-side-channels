package main

import (
	"log"
	"strings"
	"testing"

	"github.com/UzL-ITS/sev-step/sevStep"
)

var toggleEvents = `
{"id":1178899,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992750961,"timestamp":"2021-07-25T11:50:59.993445685Z","have_retired_instructions":true,"retired_instructions":9467}
{"id":1178900,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992752688,"timestamp":"2021-07-25T11:50:59.993447158Z","have_retired_instructions":true,"retired_instructions":5}
{"id":1178901,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992750981,"timestamp":"2021-07-25T11:50:59.993449302Z","have_retired_instructions":true,"retired_instructions":9467}
{"id":1178902,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992752688,"timestamp":"2021-07-25T11:50:59.993450785Z","have_retired_instructions":true,"retired_instructions":5}
{"id":1178903,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992751001,"timestamp":"2021-07-25T11:50:59.993452919Z","have_retired_instructions":true,"retired_instructions":9467}
{"id":1178904,"faulted_gpa":1512153088,"error_code":21,"have_rip_info":true,"rip":93824992697684,"timestamp":"2021-07-25T11:50:59.993454472Z","have_retired_instructions":true,"retired_instructions":16}
{"id":1178905,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992748864,"timestamp":"2021-07-25T11:50:59.993456115Z","have_retired_instructions":true,"retired_instructions":5}
{"id":1178906,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992753008,"timestamp":"2021-07-25T11:50:59.993457638Z","have_retired_instructions":true,"retired_instructions":19}
{"id":1178907,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992748942,"timestamp":"2021-07-25T11:50:59.993625848Z","have_retired_instructions":true,"retired_instructions":2509820}
{"id":1178908,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992752688,"timestamp":"2021-07-25T11:50:59.99362736Z","have_retired_instructions":true,"retired_instructions":5}
{"id":1178909,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992748956,"timestamp":"2021-07-25T11:50:59.993629515Z","have_retired_instructions":true,"retired_instructions":9467}
{"id":1178910,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992752688,"timestamp":"2021-07-25T11:50:59.993630977Z","have_retired_instructions":true,"retired_instructions":5}
{"id":1178911,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992748974,"timestamp":"2021-07-25T11:50:59.993633111Z","have_retired_instructions":true,"retired_instructions":9467}
{"id":1178912,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992752096,"timestamp":"2021-07-25T11:50:59.993634704Z","have_retired_instructions":true,"retired_instructions":641}
{"id":1178913,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992751152,"timestamp":"2021-07-25T11:50:59.993636177Z","have_retired_instructions":true,"retired_instructions":24}
{"id":1178914,"faulted_gpa":1422700544,"error_code":21,"have_rip_info":true,"rip":93824992752212,"timestamp":"2021-07-25T11:50:59.99363775Z","have_retired_instructions":true,"retired_instructions":445}
{"id":1178915,"faulted_gpa":1422696448,"error_code":21,"have_rip_info":true,"rip":93824992748993,"timestamp":"2021-07-25T11:50:59.993639243Z","have_retired_instructions":true,"retired_instructions":8}
{"id":1178916,"faulted_gpa":1512153088,"error_code":21,"have_rip_info":true,"rip":93824992697699,"timestamp":"2021-07-25T11:50:59.993640736Z","have_retired_instructions":true,"retired_instructions":13}
{"id":1178917,"faulted_gpa":1452269568,"error_code":21,"have_rip_info":true,"rip":93824992698848,"timestamp":"2021-07-25T11:50:59.993642439Z","have_retired_instructions":true,"retired_instructions":501}
`

func Test_printToggleSequences(t *testing.T) {

	seq1, err := sevStep.ParseInputFile(strings.NewReader(toggleEvents))
	if err != nil {
		t.Fatalf("Failed to parse test input : %v\n", err)
	}
	for _, v := range seq1 {
		log.Printf("GPA 0x%x\n", v.FaultedGPA)
	}
	type args struct {
		events []*sevStep.Event
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test1",
			args: args{
				events: seq1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := printToggleSequences(tt.args.events); (err != nil) != tt.wantErr {
				t.Errorf("printToggleSequences() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
