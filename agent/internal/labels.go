package internal

const (
	LabelMode         = "mode"
	LabelBuildCommit  = "build.commit"
	LabelBuildTags    = "build.tags"
	LabelAllowMemscan = "allow_memscan"

	LabelValueRemote = "remote"
	LabelValueTrue   = "true"
)

var reservedLabelKeys = map[string]struct{}{
	LabelMode:         {},
	LabelBuildCommit:  {},
	LabelBuildTags:    {},
	LabelAllowMemscan: {},
}

func IsReservedLabelKey(key string) bool {
	_, ok := reservedLabelKeys[key]
	return ok
}
