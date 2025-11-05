package logo

import "github.com/m-sec-org/d-eyes/agent/pkg/color"

var logo = [...]string{
	`    ____        ______ `,
	`   / __ \      / ____/_  _____  _____`,
	`  / / / /_____/ __/ / / / / _ \/ ___/`,
	` / /_/ /_____/ /___/ /_/ /  __(__  ) `,
	`/_____/     /_____/\__, /\___/____/ `,
	`                  /____/ `,
}

func ShowLogo() {
	color.Blue.Println(logo[0])
	color.Blue.Println(logo[1])
	color.Blue.Println(logo[2])
	color.Magenta.Println(logo[3])
	color.Magenta.Println(logo[4])
	color.Magenta.Println(logo[5])
	color.Blue.Println("                                    ———The Eyes of Darkness from Nsfocus spy on everything")
	color.Blue.Println()
}
