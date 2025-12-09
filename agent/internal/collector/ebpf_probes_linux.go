package collector

import (
	"fmt"
	"sort"
	"strings"
)

// EBPFProbeDefinition describes an attachable tracepoint/program pair.
type EBPFProbeDefinition struct {
	Name        string
	Category    string
	TraceGroup  string
	TracePoint  string
	Program     string
	Description string
	Default     bool
}

var probeCatalog = []EBPFProbeDefinition{
	// Process lifecycle.
	{
		Name:        "sys_enter_execve",
		Category:    "process",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_execve",
		Program:     "handle_sys_enter_execve",
		Description: "Captures execve system calls (process start)",
		Default:     true,
	},
	{
		Name:        "sched_process_exit",
		Category:    "process",
		TraceGroup:  "sched",
		TracePoint:  "sched_process_exit",
		Program:     "handle_sched_process_exit",
		Description: "Captures process exit events",
		Default:     true,
	},
	{
		Name:        "sys_enter_clone",
		Category:    "process",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_clone",
		Program:     "handle_sys_enter_clone",
		Description: "Captures clone events (threads/processes)",
	},
	// File system.
	{
		Name:        "sys_enter_openat",
		Category:    "filesystem",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_openat",
		Program:     "handle_sys_enter_openat",
		Description: "Tracks file open operations (path payload)",
		Default:     true,
	},
	{
		Name:        "sys_enter_write",
		Category:    "filesystem",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_write",
		Program:     "handle_sys_enter_write",
		Description: "Tracks file write operations",
	},
	{
		Name:        "sys_enter_unlinkat",
		Category:    "filesystem",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_unlinkat",
		Program:     "handle_sys_enter_unlinkat",
		Description: "Tracks file delete operations",
	},
	{
		Name:        "sys_enter_renameat",
		Category:    "filesystem",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_renameat",
		Program:     "handle_sys_enter_renameat",
		Description: "Tracks file rename operations with old/new paths",
	},
	{
		Name:        "sys_enter_mmap",
		Category:    "memory",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_mmap",
		Program:     "handle_sys_enter_mmap",
		Description: "Captures mmap address/length/protection arguments",
	},
	{
		Name:        "sys_enter_mprotect",
		Category:    "memory",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_mprotect",
		Program:     "handle_sys_enter_mprotect",
		Description: "Captures mprotect region and permission changes",
	},
	{
		Name:        "sys_enter_munmap",
		Category:    "memory",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_munmap",
		Program:     "handle_sys_enter_munmap",
		Description: "Tracks memory unmap operations",
	},
	// Networking.
	{
		Name:        "sys_enter_socket",
		Category:    "network",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_socket",
		Program:     "handle_sys_enter_socket",
		Description: "Captures socket creation",
	},
	{
		Name:        "sys_enter_connect",
		Category:    "network",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_connect",
		Program:     "handle_sys_enter_connect",
		Description: "Captures outbound connect attempts",
	},
	{
		Name:        "sys_enter_sendmsg",
		Category:    "network",
		TraceGroup:  "syscalls",
		TracePoint:  "sys_enter_sendmsg",
		Program:     "handle_sys_enter_sendmsg",
		Description: "Captures sendmsg destinations (IPv4/6/Unix)",
	},
}

type ebpfProbeRegistry struct {
	defs       []EBPFProbeDefinition
	index      map[string]EBPFProbeDefinition
	categories map[string][]EBPFProbeDefinition
	defaults   []string
}

func newEBPFProbeRegistry() *ebpfProbeRegistry {
	reg := &ebpfProbeRegistry{
		defs:       append([]EBPFProbeDefinition(nil), probeCatalog...),
		index:      make(map[string]EBPFProbeDefinition),
		categories: make(map[string][]EBPFProbeDefinition),
	}
	for _, def := range reg.defs {
		reg.index[strings.ToLower(def.Name)] = def
		cat := strings.ToLower(def.Category)
		reg.categories[cat] = append(reg.categories[cat], def)
		if def.Default {
			reg.defaults = append(reg.defaults, def.Name)
		}
	}
	sort.Strings(reg.defaults)
	return reg
}

func (r *ebpfProbeRegistry) List() []EBPFProbeDefinition {
	if r == nil {
		return nil
	}
	return append([]EBPFProbeDefinition(nil), r.defs...)
}

func (r *ebpfProbeRegistry) DefaultNames() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.defaults...)
}

func (r *ebpfProbeRegistry) Resolve(selections []string) ([]ebpfProbe, error) {
	if r == nil {
		return nil, fmt.Errorf("probe registry not initialised")
	}
	seen := make(map[string]struct{})
	var defs []EBPFProbeDefinition
	appendDef := func(def EBPFProbeDefinition) {
		if _, ok := seen[def.Name]; ok {
			return
		}
		seen[def.Name] = struct{}{}
		defs = append(defs, def)
	}
	for _, sel := range selections {
		name := strings.TrimSpace(sel)
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "category:") {
			cat := strings.ToLower(strings.TrimPrefix(name, "category:"))
			if items, ok := r.categories[cat]; ok {
				for _, def := range items {
					appendDef(def)
				}
				continue
			}
			return nil, fmt.Errorf("unknown probe category %q", cat)
		}
		def, ok := r.index[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown ebpf probe %q", name)
		}
		appendDef(def)
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("no ebpf probes resolved")
	}
	probes := make([]ebpfProbe, 0, len(defs))
	for _, def := range defs {
		probes = append(probes, ebpfProbe{
			Name:       def.Name,
			TraceGroup: def.TraceGroup,
			TracePoint: def.TracePoint,
			Program:    def.Program,
		})
	}
	return probes, nil
}
