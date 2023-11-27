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

func Usage() {

	usage := `Usage: D-Eyes.exe filescan/processcan/info [other arguments...]
  -info string
        Basic information options: host, users, netstat, task, autoruns, summary.(For 'basicInfo' function)
  -path string
        The filepath where you want to scan. Such as C:// (windows) or / (linux).(For 'filescan' function)
  -pid int
        The pid of process you want to scan. (optional) (Only For processcan.'-1' means all processes.) (default -1)
  -rule string
        The rule you want to scan with. (optional)
  -thread int
        The default thread is 5. (optional) (Only For filescan) (default 5)`
	fmt.Print(usage)
}
