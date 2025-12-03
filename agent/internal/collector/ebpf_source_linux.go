//go:build linux

package collector

import _ "embed"

//go:embed ebpf/programs/syscall.bpf.c
var ebpfSyscallProgramSource string
