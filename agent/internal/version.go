package internal

import "strings"

var (
	buildCommit string
	buildTags   string
)

func CLIVersion() string {
	return strings.TrimSpace(version)
}

func BuildCommit() string {
	return strings.TrimSpace(buildCommit)
}

func BuildTags() string {
	return strings.TrimSpace(buildTags)
}
