package logo

import (
	"fmt"
	"github.com/daviddengcn/go-colortext"
)

var logo = [...]string{
	`    ____        ______ `,
	`   / __ \      / ____/_  _____  _____`,
	`  / / / /_____/ __/ / / / / _ \/ ___/`,
	` / /_/ /_____/ /___/ /_/ /  __(__  ) `,
	`/_____/     /_____/\__, /\___/____/ `,
	`                  /____/ `,
}

func ShowLogo() {
	ct.Foreground(ct.Blue, true)
	fmt.Println(logo[0])
	fmt.Println(logo[1])

	ct.ResetColor()
	ct.Foreground(ct.Blue, true)
	fmt.Println(logo[2])
	ct.Foreground(ct.Magenta, true)
	fmt.Println(logo[3])
	ct.ResetColor()

	ct.Foreground(ct.Magenta, true)
	fmt.Println(logo[4])
	ct.ResetColor()

	ct.Foreground(ct.Magenta, true)
	fmt.Println(logo[5])
	ct.ResetColor()

	ct.Foreground(ct.Blue, true)
	fmt.Println("                                  ———The Eyes of Darkness from Nsfocus spy on everything")
	ct.ResetColor()
	fmt.Println()
}
