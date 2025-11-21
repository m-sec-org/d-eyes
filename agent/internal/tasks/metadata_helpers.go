package tasks

import (
	"net"
	"path/filepath"
	"strings"
)

func mergeMetadata(dst map[string]string, src map[string]string) {
	if len(src) == 0 {
		return
	}
	if dst == nil {
		return
	}
	for k, v := range src {
		if strings.TrimSpace(k) == "" {
			continue
		}
		dst[k] = v
	}
}

func cloneMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func looksLikePath(value string) string {
	clean := strings.Trim(strings.TrimSpace(value), `"'`)
	if clean == "" {
		return ""
	}
	if strings.Contains(clean, "/") || strings.Contains(clean, `\`) {
		return clean
	}
	if filepath.Ext(clean) != "" && len(clean) > len(filepath.Ext(clean)) {
		return clean
	}
	return ""
}

func isPublicIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}
