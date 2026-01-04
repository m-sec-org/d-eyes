//go:build !windows

package detect

func loadInterfaceExtras() (map[int]interfaceExtras, map[string]interfaceExtras, []string) {
	return nil, nil, nil
}
