package main

import (
	"log"
	"os"

	"d-eyes/cmd"
	"d-eyes/pkg/logo"
	_ "d-eyes/plugins"
)

func main() {
	logo.ShowLogo()
	cmd.ParseGlobalOptions()
	err := cmd.App.Run(os.Args)
	if err != nil {
		log.Fatal(err)
		return
	}
}
