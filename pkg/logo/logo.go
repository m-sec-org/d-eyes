package logo

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/pkg/color"
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
	fmt.Println(color.Blue.Sprintf(logo[0]))
	fmt.Println(color.Blue.Sprintf(logo[1]))

	fmt.Println(color.Blue.Sprintf(logo[2]))

	fmt.Println(color.Magenta.Sprintf(logo[3]))

	fmt.Println(color.Magenta.Sprintf(logo[4]))

	fmt.Println(color.Magenta.Sprintf(logo[5]))

	fmt.Println(color.Blue.Sprintf("                                    ———The Eyes of Darkness from Nsfocus spy on everything"))

	fmt.Println()
}
