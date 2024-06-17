//go:build windows

package detect

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"strings"
)

var VulOption *VulOptions

type VulOptions struct {
	internal.BaseOption
	Vulnerability int
}

func init() {
	VulOption = NewDetectPluginVul()
	internal.RegisterDetectSubcommands(VulOption)

}
func NewDetectPluginVul() *VulOptions {
	return &VulOptions{
		internal.BaseOption{
			// 漏洞检测
			Name:        "check  Autorun",
			Author:      "msec",
			Description: "Command to check for vulnerabilities on the host",
		},
		0,
	}
}
func (autorun *VulOptions) InitCommand() []*cli.Command {
	return []*cli.Command{{
		Name:    "vulnerability",
		Aliases: []string{"vul"},
		Usage:   "check Exchange Server OWASSRF exploitation",
		Action:  autorun.Action,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "vulnerabilityFlag",
				Aliases:     []string{"v"},
				Usage:       "-v 1 (1 is to check Exchange Server OWASSRF exploitation)",
				Destination: &VulOption.Vulnerability,
			},
		},
	}}
}

func (autorun *VulOptions) Action(_ *cli.Context) error {
	switch autorun.Vulnerability {
	case 1:
		checkExchangeServerOWASSRF("")
	default:
		fmt.Println("Please enter the number of vulnerability exploitation you want to check.")
		fmt.Println()
		fmt.Println(color.Yellow.Sprint("Currently supported vulnerability exploitation list:"))
		fmt.Println("     1: Exchange Server OWASSRF")
		fmt.Println()
		fmt.Print("Like this, if you want to check 'Exchange Server OWASSRF' exploitation, just input ")
		fmt.Println(color.Yellow.Sprint("'D-Eyes de vul -v 1'"))
	}
	return nil
}

func checkExchangeServerOWASSRF(path string) {
	if path == "" {
		path = "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Logging\\CmdletInfra\\Powershell-Proxy\\Http"
	}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		fmt.Println("Didn't find the directory '", path, "' on this host!")
		return
	}
	var logs []string
	var paths []string
	var users []string
	var successDocs []string
	var failDocs []string
	fmt.Println(color.Green.Sprint("Checking the Rps_Http logs in '", path, "'..."))

	files, err := filepath.Glob(path + "/*Rps_Http_20*")
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(files) == 0 {
		fmt.Println("Not found Rps_Http logs in the directory '", path, "'")
		return
	}
	for _, file := range files {
		csvFile, err := os.Open(file)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer csvFile.Close()

		reader := csv.NewReader(bufio.NewReader(csvFile))
		reader.Comma = ','
		reader.FieldsPerRecord = -1

		csvData, err := reader.ReadAll()
		if err != nil {
			fmt.Println(err)
			return
		}

		for _, record := range csvData {
			if len(record) < 30 {
				continue
			}
			ua := record[29]
			if ua != "ClientInfo" && ua != "Microsoft WinRM Client" && ua != "Exchange BackEnd Probes" && strings.ContainsAny(ua, "a-zA-Z0-9") {
				time := record[0]
				src := strings.Replace(record[15], " ", " -> ", -1)
				server := record[16]
				frontend := record[17]
				status := record[18]
				user := record[12]

				if status != "200" {
					failDocs = append(failDocs, time+" [FAILURE: "+status+" ] Path: "+src+" -> "+frontend+" -> "+server+" as User: [ "+user+" ]")
				} else {
					successDocs = append(successDocs, time+" [SUCCESS: "+status+" ] Path: "+src+" -> "+frontend+" -> "+server+" as User: [ "+user+" ]")
				}
				paths = append(paths, src+" -> "+frontend+" -> "+server)
				if strings.ContainsAny(user, "a-zA-Z0-9") {
					users = append(users, user)
				}
				logs = append(logs, file)
			}
		}
	}
	paths = removeDuplicates(paths)
	users = removeDuplicates(users)
	logs = removeDuplicates(logs)
	if len(successDocs) > 0 || len(failDocs) > 0 {
		fmt.Println()
		fmt.Println(color.Red.Sprint("Something Suspicious Found !!!"))
		fmt.Println()
		if len(successDocs) > 0 {
			fmt.Println(color.Yellow.Sprint(len(successDocs), "instances of possible successful proxied exploitation found using UA indicator:"))
			for _, s := range successDocs {
				fmt.Println("	", s)
			}
		}
		if len(failDocs) > 0 {
			fmt.Println(color.Yellow.Sprint(len(failDocs), "instances of failed proxied exploitation attempts found using UA indicator"))
			for _, f := range failDocs {
				fmt.Println("	", f)
			}
		}
		fmt.Println(color.Yellow.Sprint("Network paths used for exploitation attempts"))
		for _, p := range paths {
			fmt.Println("	", p)
		}
		fmt.Println(color.Yellow.Sprint("Compromised users:"))
		for _, u := range users {
			fmt.Println("	", u)
		}
		fmt.Println(color.Yellow.Sprint("The above information is obtained from the following files:"))
		for _, l := range logs {
			fmt.Println("	", l)
		}
	} else {
		fmt.Println()
		fmt.Println(color.Green.Sprint("Nothing Suspicious Found !"))
	}
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	var result []string
	for v := range elements {
		if encountered[elements[v]] == true {
		} else {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}
