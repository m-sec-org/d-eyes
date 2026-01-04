package memscan

import (
	"errors"
	"time"
)

var ErrUnsupportedPlatform = errors.New("memscan is only supported on Windows")

type RegionFilter string

const (
	// FilterRWX selects committed pages that are executable and writable.
	FilterRWX RegionFilter = "rwx"
	// FilterCommitted selects committed pages regardless of protection (still skips guard/noaccess).
	FilterCommitted RegionFilter = "committed"
)

const (
	DegradedMaxBytes   = "max-bytes"
	DegradedMaxRegions = "max-regions"
	DegradedTimeout    = "timeout"
	DegradedCanceled   = "canceled"
)

// Options controls region selection and guardrails.
type Options struct {
	Filter     RegionFilter
	ChunkSize  int
	MaxBytes   uint64
	MaxRegions int
	Timeout    time.Duration
}

func (o Options) normalize() Options {
	if o.Filter == "" {
		o.Filter = FilterRWX
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = 256 * 1024
	}
	return o
}

// Region mirrors Windows MEMORY_BASIC_INFORMATION essentials.
type Region struct {
	Base    uintptr
	Size    uintptr
	State   uint32
	Protect uint32
	Type    uint32
}

func (r Region) End() uintptr {
	return r.Base + r.Size
}

// Chunk describes a successfully read memory slice.
// Data is only valid for the duration of the callback that receives it.
type Chunk struct {
	Region  Region
	Address uintptr
	Data    []byte
}

// Stats captures guardrail decisions and progress.
type Stats struct {
	RegionsEnumerated int
	RegionsMatched    int
	RegionsRead       int
	BytesRead         uint64
	ReadAttempts      int
	ReadErrors        int
	ReadErrorsByKind  map[ReadErrorKind]int
	Degraded          bool
	DegradedReasons   []string
}

func (s *Stats) addDegradedReason(reason string) {
	reason = normalizeReason(reason)
	for _, existing := range s.DegradedReasons {
		if existing == reason {
			return
		}
	}
	s.DegradedReasons = append(s.DegradedReasons, reason)
	s.Degraded = true
}

func (s *Stats) addReadError(kind ReadErrorKind) {
	kind = normalizeReadErrorKind(kind)
	s.ReadErrors++
	if s.ReadErrorsByKind == nil {
		s.ReadErrorsByKind = make(map[ReadErrorKind]int, 4)
	}
	s.ReadErrorsByKind[kind]++
}

func normalizeReason(reason string) string {
	switch reason {
	case DegradedMaxBytes, DegradedMaxRegions, DegradedTimeout, DegradedCanceled:
		return reason
	default:
		return "unknown"
	}
}

func normalizeReadErrorKind(kind ReadErrorKind) ReadErrorKind {
	switch kind {
	case ReadErrorAccessDenied,
		ReadErrorInvalidAddress,
		ReadErrorInvalidParameter,
		ReadErrorNoAccess,
		ReadErrorOther,
		ReadErrorPartialCopy,
		ReadErrorZeroRead:
		return kind
	default:
		return ReadErrorOther
	}
}

// Windows constants used for filtering.
const (
	memCommit = 0x1000

	pageNoAccess         = 0x01
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80
	pageGuard            = 0x100
)

func isReadableCommitted(region Region) bool {
	if region.State != memCommit {
		return false
	}
	if region.Protect == 0 {
		return false
	}
	if region.Protect&pageNoAccess != 0 {
		return false
	}
	if region.Protect&pageGuard != 0 {
		return false
	}
	return true
}

func isRWXProtect(protect uint32) bool {
	if protect == 0 {
		return false
	}
	if protect&pageNoAccess != 0 {
		return false
	}
	if protect&pageGuard != 0 {
		return false
	}
	base := protect & 0xFF
	return base == pageExecuteReadWrite || base == pageExecuteWriteCopy
}
