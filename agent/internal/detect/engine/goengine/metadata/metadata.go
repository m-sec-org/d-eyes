package metadata

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// FileMetadata 保存关于样本的基本描述。
type FileMetadata struct {
	Size     int
	Hash     string
	families map[string]bool
}

// Extract 通过原始字节推导基础元信息（文件族、哈希等）。
func Extract(data []byte) *FileMetadata {
	meta := &FileMetadata{
		Size:     len(data),
		Hash:     hashBytes(data),
		families: make(map[string]bool),
	}
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		meta.families["pe"] = true
	}
	if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		meta.families["elf"] = true
	}
	if len(data) >= 4 {
		word := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		switch word {
		case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
			meta.families["mach"] = true
		}
	}
	return meta
}

// SupportsFamily 判断文件是否属于某一族（例如 pe/elf）。
func (m *FileMetadata) SupportsFamily(name string) bool {
	if m == nil {
		return false
	}
	if len(m.families) == 0 {
		return false
	}
	return m.families[strings.ToLower(name)]
}

func hashBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
