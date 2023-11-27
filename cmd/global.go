package cmd

var GlobalOption GlobalOptions

type GlobalOptions struct {
	Path   string
	Rule   string
	Pid    int
	Thread int
	Debug  bool
}
