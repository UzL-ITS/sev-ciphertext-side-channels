package pfFingerprint

import "pfFingerprint/trigger"

type OSSLAttackConfigECDH struct {
	BaseGPA     uint64 `json:"base_gpa"`
	Fe64GPA     uint64 `json:"fe_64_gpa"`
	StackBufGPA uint64 `json:"stack_buf_gpa"`
}

type OSSHAttackConfigEdDSA struct {
	ChooseTGPA          uint64                      `json:"choose_tgpa"`
	Fe64GPA             uint64                      `json:"fe_64_gpa"`
	StackBufGPA         uint64                      `json:"stack_buf_gpa"`
	MemAccessesPerCycle int                         `json:"mem_accesses_per_cycle"`
	SigMsg              trigger.SSHSignatureMessage `json:"sig_msg"`
	MainLoopCycles      int                         `json:"main_loop_cylces"`
	StackBufAlignment   int                         `json:"stack_buf_alignment"`
	StackBufBytes       int                         `json:"stack_buf_bytes"`
}
