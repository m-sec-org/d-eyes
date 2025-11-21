package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func respondCacheKey(module string, req TaskRequest) string {
	targets := strings.Join(parseTargets(req), ",")
	flagHash := hashFlags(req.Flags)
	return fmt.Sprintf("%s|profile=%s|targets=%s|flags=%s", module, strings.ToLower(strings.TrimSpace(req.Profile)), targets, flagHash)
}

func hashFlags(flags map[string]any) string {
	if len(flags) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(flags))
	for k := range flags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, k := range keys {
		builder.WriteString(k)
		builder.WriteString("=")
		builder.WriteString(fmt.Sprint(flags[k]))
		builder.WriteString(";")
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:8])
}
