package memscan

import (
	"errors"
	"syscall"
)

type ReadErrorKind string

const (
	ReadErrorPartialCopy      ReadErrorKind = "partial-copy"
	ReadErrorAccessDenied     ReadErrorKind = "access-denied"
	ReadErrorNoAccess         ReadErrorKind = "no-access"
	ReadErrorInvalidAddress   ReadErrorKind = "invalid-address"
	ReadErrorInvalidParameter ReadErrorKind = "invalid-parameter"
	ReadErrorZeroRead         ReadErrorKind = "zero-read"
	ReadErrorOther            ReadErrorKind = "other"
)

const (
	winErrorAccessDenied     syscall.Errno = 5
	winErrorInvalidParameter syscall.Errno = 87
	winErrorPartialCopy      syscall.Errno = 299
	winErrorInvalidAddress   syscall.Errno = 487
	winErrorNoAccess         syscall.Errno = 998
)

func classifyReadError(err error) ReadErrorKind {
	if err == nil {
		return ""
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case winErrorPartialCopy:
			return ReadErrorPartialCopy
		case winErrorAccessDenied:
			return ReadErrorAccessDenied
		case winErrorNoAccess:
			return ReadErrorNoAccess
		case winErrorInvalidAddress:
			return ReadErrorInvalidAddress
		case winErrorInvalidParameter:
			return ReadErrorInvalidParameter
		}
	}

	return ReadErrorOther
}

// ClassifyReadError maps a platform error returned by ReadProcessMemory (or similar syscall
// wrappers) to a stable ReadErrorKind value.
func ClassifyReadError(err error) ReadErrorKind {
	return classifyReadError(err)
}
