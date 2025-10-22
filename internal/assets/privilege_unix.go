//go:build !windows

package assets

import "os"

func isPrivilegedUser() bool {
	return os.Geteuid() == 0
}
