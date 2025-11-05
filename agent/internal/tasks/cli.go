package tasks

import "github.com/urfave/cli/v2"

// ExtractFlags 从 CLI 上下文采集所有 flag 值
func ExtractFlags(c *cli.Context) map[string]any {
	flags := make(map[string]any)
	if c == nil {
		return flags
	}
	for _, name := range c.FlagNames() {
		flags[name] = c.Value(name)
	}
	return flags
}
