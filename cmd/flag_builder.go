package cmd

import "github.com/urfave/cli/v2"

// BuildPathFlag ...
func BuildPathFlag(dst *string, DefaultValue string, Required bool) cli.Flag {
	return &cli.StringFlag{
		Name:        "path",
		Aliases:     []string{"P"},
		Value:       DefaultValue,
		Destination: dst,
		Required:    Required,
	}
}

func BuildRuleFlag(dst *string, DefaultValue string, Required bool) cli.Flag {
	return &cli.StringFlag{
		Name:        "rule",
		Aliases:     []string{"r"},
		Value:       DefaultValue,
		Destination: dst,
		Required:    Required,
	}
}

func BuildThreadFlag(dst *int, DefaultValue int, Required bool) cli.Flag {
	return &cli.IntFlag{
		Name:        "thread",
		Aliases:     []string{"t"},
		Value:       DefaultValue,
		Destination: dst,
		Required:    Required,
	}
}
