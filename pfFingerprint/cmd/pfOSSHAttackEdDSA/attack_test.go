package main

import (
	"reflect"
	"testing"

	"github.com/UzL-ITS/sev-step/sevStep"
)

func Test_extractStackPage(t *testing.T) {

	//2021/08/14 11:13:35 ID 285, FaultedGPA 6efa1000, HaveRip true, RIP ffffffff810dbf96, Timestamp Aug 14 11:13:35.555548743 Retired Instructions not measured Error Code User , RetInstr 0
	//2021/08/14 11:13:35 ID 286, FaultedGPA 752b9000, HaveRip true, RIP 5555555d1e60, Timestamp Aug 14 11:13:35.555552319 Retired Instructions not measured Error Code Write User , RetInstr 0
	//2021/08/14 11:13:35 ID 287, FaultedGPA 7c006000, HaveRip true, RIP 5555555d1e60, Timestamp Aug 14 11:13:35.555555015 Retired Instructions not measured Error Code Write User , RetInstr 0
	//2021/08/14 11:13:35 ID 288, FaultedGPA 6f850000, HaveRip true, RIP 5555555d1e60, Timestamp Aug 14 11:13:35.555557920 Retired Instructions not measured Error Code Write User , RetInstr 0
	//2021/08/14 11:13:35 ID 289, FaultedGPA 6a596000, HaveRip true, RIP 5555555d1e70, Timestamp Aug 14 11:13:35.555561487 Retired Instructions not measured Error Code Write User , RetInstr 0
	//2021/08/14 11:13:35 ID 290, FaultedGPA 6a569000, HaveRip true, RIP 5555555d1e70, Timestamp Aug 14 11:13:35.555564483 Retired Instructions not measured Error Code Write User , RetInstr 0
	//2021/08/14 11:13:35 ID 291, FaultedGPA 7c20a000, HaveRip true, RIP 5555555d1e70, Timestamp Aug 14 11:13:35.555567388 Retired Instructions not measured Error Code Write User , RetInstr 0
	//2021/08/14 11:13:35 ID 292, FaultedGPA 5a1ba000, HaveRip true, RIP 5555555d1e70, Timestamp Aug 14 11:13:35.555570334 Retired Instructions not measured Error Code User , RetInstr 0
	//2021/08/14 11:13:35 ID 293, FaultedGPA 3b1b9000, HaveRip true, RIP 5555555d1e73, Timestamp Aug 14 11:13:35.555573570 Retired Instructions not measured Error Code User , RetInstr 0
	//2021/08/14 11:13:35 ID 294, FaultedGPA 57241000, HaveRip true, RIP 5555555d1e8c, Timestamp Aug 14 11:13:35.555576746 Retired Instructions not measured Error Code User , RetInstr 0
	events1 := []*sevStep.Event{
		{
			ID:                  0,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  1,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  2,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  3,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  4,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  5,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  6,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  7,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorWrite | sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  8,
			FaultedGPA:          0x5a1ba000,
			ErrorCode:           uint32(sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  9,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
		{
			ID:                  10,
			FaultedGPA:          0x6efa1000,
			ErrorCode:           uint32(sevStep.PfErrorUser),
			HaveRipInfo:         true,
			RetiredInstructions: 0,
		},
	}
	type args struct {
		events []*sevStep.Event
	}
	tests := []struct {
		name  string
		args  args
		want  *sevStep.Event
		want1 bool
	}{
		{
			name: "Normal",
			args: args{
				events: events1,
			},
			want:  events1[8],
			want1: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := extractStackPage(tt.args.events)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractStackPage() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("extractStackPage() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
