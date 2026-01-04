package memscan

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyReadErrorMapsCommonWindowsErrnos(t *testing.T) {
	require.Equal(t, ReadErrorKind(""), classifyReadError(nil))
	require.Equal(t, ReadErrorPartialCopy, classifyReadError(syscall.Errno(299)))
	require.Equal(t, ReadErrorAccessDenied, classifyReadError(syscall.Errno(5)))
	require.Equal(t, ReadErrorNoAccess, classifyReadError(syscall.Errno(998)))
	require.Equal(t, ReadErrorInvalidAddress, classifyReadError(syscall.Errno(487)))
	require.Equal(t, ReadErrorInvalidParameter, classifyReadError(syscall.Errno(87)))
	require.Equal(t, ReadErrorOther, classifyReadError(syscall.Errno(123456)))
}
