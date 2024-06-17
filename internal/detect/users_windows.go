//go:build windows

package detect

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	deUtils "github.com/m-sec-org/d-eyes/internal/detect/utils"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/urfave/cli/v2"
)

var UserOption *UserOptions

func init() {
	UserOption = NewDetectPluginUser()
	internal.RegisterDetectSubcommands(UserOption)
}

type UserOptions struct {
	internal.BaseOption
}

func NewDetectPluginUser() *UserOptions {
	return &UserOptions{
		BaseOption: internal.BaseOption{
			// 显示所有用户
			Name:        "user check",
			Author:      "msec",
			Description: "Command for displaying all the users on the host",
		},
	}
}
func (userOption *UserOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "user",
			Usage:  "Command for displaying all the users on the host",
			Action: userOption.Action,
		},
	}
}
func (userOption *UserOptions) Action(c *cli.Context) error {
	fmt.Println(color.Green.Sprint("AllUsers:"))
	usersList := deUtils.GetWindowsUser()

	for _, user := range usersList {
		fmt.Print(color.Green.Sprint("* "))
		fmt.Println(color.Green.Sprint(user))
	}
	return nil
}
