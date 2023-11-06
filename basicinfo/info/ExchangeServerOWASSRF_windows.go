package info

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gookit/color"
)

func CheckExchangeServerOWASSRF(path string) {
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

	color.Info.Println("Checking the Rps_Http logs in '", path, "'...")

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
		color.Error.Println("Something Suspicious Found !!!")
		fmt.Println()
		if len(successDocs) > 0 {
			color.Warn.Println(len(successDocs), "instances of possible successful proxied exploitation found using UA indicator:")
			for _, s := range successDocs {
				fmt.Println("	", s)
			}
		}
		if len(failDocs) > 0 {
			color.Warn.Println(len(failDocs), "instances of failed proxied exploitation attempts found using UA indicator")
			for _, f := range failDocs {
				fmt.Println("	", f)
			}
		}
		color.Warn.Println("Network paths used for exploitation attempts:")
		for _, p := range paths {
			fmt.Println("	", p)
		}
		color.Warn.Println("Compromised users:")
		for _, u := range users {
			fmt.Println("	", u)
		}
		color.Warn.Println("The above information is obtained from the following files:")
		for _, l := range logs {
			fmt.Println("	", l)
		}
	} else {
		fmt.Println()
		color.Info.Println("Nothing Suspicious Found !")
	}
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}
	for v := range elements {
		if encountered[elements[v]] == true {
		} else {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}
