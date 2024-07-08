package main

import (
	"fmt"
	"os"
	"time"

	"github.com/m-sec-org/d-eyes/internal"
	_ "github.com/m-sec-org/d-eyes/internal"
	_ "github.com/m-sec-org/d-eyes/internal/detect"
	_ "github.com/m-sec-org/d-eyes/internal/sbom/java"
	_ "github.com/m-sec-org/d-eyes/internal/sbom/python"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/m-sec-org/d-eyes/pkg/logo"
	"github.com/m-sec-org/d-eyes/pkg/logs"
)

func init() {
	logo.ShowLogo()
	logs.InitLog()
}
func main() {
	start := time.Now()
	defer func() {
		sub := time.Now().Sub(start)
		fmt.Println()
		fmt.Println(color.Green.Sprintf("Thank you for using d-eyes, this run took %f seconds.", sub.Seconds()))
	}()
	err := internal.App.Run(os.Args)
	if err != nil {
		fmt.Println(color.Magenta.Sprintf("参数错误，请检查参数"))
		fmt.Println(err.Error())
		os.Exit(0)
	}

}
