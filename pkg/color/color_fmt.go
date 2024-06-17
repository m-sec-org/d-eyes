package color

import "github.com/fatih/color"

var (
	Yellow  *color.Color
	Green   *color.Color
	Magenta *color.Color
	Red     *color.Color
	Blue    *color.Color
)

func init() {
	Yellow = color.New(color.FgYellow, color.Bold)
	Green = color.New(color.FgGreen, color.Bold)
	Magenta = color.New(color.FgMagenta, color.Bold)
	// Foreground text colors
	Blue = color.New(color.FgBlue, color.Bold)
	Red = color.New(color.FgRed, color.Bold)
}
