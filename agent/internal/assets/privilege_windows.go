//go:build windows

package assets

func isPrivilegedUser() bool {
	// Windows privilege detection is platform specific; assume non-privileged by default.
	return false
}
