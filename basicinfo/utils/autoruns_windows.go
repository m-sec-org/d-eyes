package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	files "github.com/botherder/go-files"
	"github.com/mattn/go-shellwords"
	"golang.org/x/sys/windows/registry"
)

// Just return a string value for a given registry root Key.
func registryToString(reg registry.Key) string {
	if reg == registry.LOCAL_MACHINE {
		return "LOCAL_MACHINE"
	} else if reg == registry.CURRENT_USER {
		return "CURRENT_USER"
	} else {
		return ""
	}
}

func parsePath(entryValue string) ([]string, error) {
	if entryValue == "" {
		return nil, errors.New("empty path")
	}
	if strings.HasPrefix(entryValue, `\??\`) {
		entryValue = entryValue[4:]
	}
	// do some typical replacements
	if len(entryValue) >= 11 && strings.ToLower(entryValue[:11]) == "\\systemroot" {
		entryValue = strings.Replace(entryValue, entryValue[:11], os.Getenv("SystemRoot"), -1)
	}
	if len(entryValue) >= 8 && strings.ToLower(entryValue[:8]) == "system32" {
		entryValue = strings.Replace(entryValue, entryValue[:8], fmt.Sprintf("%s\\System32", os.Getenv("SystemRoot")), -1)
	}
	// replace environment variables
	entryValue, err := registry.ExpandString(entryValue)
	if err != nil {
		return []string{}, err
	}
	// We clean the path for proper backslashes.
	entryValue = strings.Replace(entryValue, "\\", "\\\\", -1)
	// Check if the whole entry is an executable and clean the file path.
	if v, err := cleanPath(entryValue); err == nil {
		return []string{v}, nil
	}
	// Otherwise we can split the entry for executable and arguments
	parser := shellwords.NewParser()
	args, err := parser.Parse(entryValue)
	if err != nil {
		return []string{}, err
	}
	// If the split worked, find the correct path to the executable and clean
	// the file path.
	if len(args) > 0 {
		if v, err := cleanPath(args[0]); err == nil {
			args[0] = v
		}
	}
	return args, nil
}

func stringToAutorun(entryType string, entryLocation string, entryValue string, toParse bool, entry string) *Autorun {
	var imagePath = entryValue
	var launchString = entryValue
	var argsString = ""

	// TODO: This optional parsing is quite spaghetti. To change.
	if toParse == true {
		args, err := parsePath(entryValue)

		if err == nil {
			if len(args) > 0 {
				imagePath = args[0]
				if len(args) > 1 {
					argsString = strings.Join(args[1:], " ")
				}
			}
		}
	}

	md5, _ := files.HashFile(imagePath, "md5")
	sha1, _ := files.HashFile(imagePath, "sha1")
	sha256, _ := files.HashFile(imagePath, "sha256")

	newAutorun := Autorun{
		Type:         entryType,
		Location:     entryLocation,
		ImagePath:    imagePath,
		ImageName:    filepath.Base(imagePath),
		Arguments:    argsString,
		MD5:          md5,
		SHA1:         sha1,
		SHA256:       sha256,
		Entry:        entry,
		LaunchString: launchString,
	}

	return &newAutorun
}

// This function invokes all the platform-dependant functions.
func getAutoruns() (records []*Autorun) {
	records = append(records, windowsGetCurrentVersionRun()...)
	//records = append(records, windowsGetServices()...)
	records = append(records, windowsGetStartupFiles()...)
	// records = append(records, windowsGetTasks()...)

	return
}

// This function enumerates items registered through CurrentVersion\Run.
func windowsGetCurrentVersionRun() (records []*Autorun) {
	regs := []registry.Key{
		registry.LOCAL_MACHINE,
		registry.CURRENT_USER,
	}

	keyNames := []string{
		"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
		"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}

	// We loop through HKLM and HKCU.
	for _, reg := range regs {
		// We loop through the keys we're interested in.
		for _, keyName := range keyNames {
			// Open registry key.
			key, err := registry.OpenKey(reg, keyName, registry.READ)
			if err != nil {
				continue
			}

			// Enumerate value names.
			names, err := key.ReadValueNames(0)
			if err != nil {
				key.Close()
				continue
			}

			for _, name := range names {
				// For each entry we get the string value.
				value, _, err := key.GetStringValue(name)
				if err != nil || value == "" {
					continue
				}

				imageLocation := fmt.Sprintf("%s\\%s", registryToString(reg), keyName)

				/*reTime,err:=key.Stat()
				if err != nil  {
					fmt.Println(err)
					continue
				}
				reTime.ModTime()*/
				newAutorun := stringToAutorun("Autoruns", imageLocation, value, true, name)

				// Add the new autorun to the records.
				records = append(records, newAutorun)
			}
			key.Close()
		}
	}

	return
}

// This function enumerates Windows Services.
func windowsGetServices() (records []*Autorun) {
	var reg registry.Key = registry.LOCAL_MACHINE
	var servicesKey string = "System\\CurrentControlSet\\Services"

	// Open the registry key.
	key, err := registry.OpenKey(reg, servicesKey, registry.READ)
	if err != nil {
		return
	}

	// Enumerate subkeys.
	names, err := key.ReadSubKeyNames(0)
	key.Close()
	if err != nil {
		return
	}

	for _, name := range names {
		// We open each subkey.
		subkeyPath := fmt.Sprintf("%s\\%s", servicesKey, name)
		subkey, err := registry.OpenKey(reg, subkeyPath, registry.READ)
		if err != nil {
			continue
		}

		// Check if there is an ImagePath value.
		imagePath, _, err := subkey.GetStringValue("ImagePath")
		subkey.Close()
		// If not, we skip to the next one.
		if err != nil {
			continue
		}

		imageLocation := fmt.Sprintf("%s\\%s", registryToString(reg), subkeyPath)

		// We pass the value string to a function to return an Autorun.
		newAutorun := stringToAutorun("service", imageLocation, imagePath, true, "")

		// Add the new autorun to the records.
		records = append(records, newAutorun)
	}

	return
}

// %ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp
// %AppData%\Microsoft\Windows\Start Menu\Programs\Startup
func windowsGetStartupFiles() (records []*Autorun) {
	// We look for both global and user Startup folders.
	folders := []string{
		os.Getenv("ProgramData"),
		os.Getenv("AppData"),
	}

	// The base path is the same for both.
	var startupBasepath string = "Microsoft\\Windows\\Start Menu\\Programs\\StartUp"

	for _, folder := range folders {
		// Get the full path.
		startupPath := filepath.Join(folder, startupBasepath)

		// Get list of files in folder.
		filesList, err := ioutil.ReadDir(startupPath)
		if err != nil {
			continue
		}

		// Loop through all files in folder.
		for _, fileEntry := range filesList {
			// We skip desktop.ini files.
			if fileEntry.Name() == "desktop.ini" {
				continue
			}

			filePath := filepath.Join(startupPath, fileEntry.Name())

			// Instantiate new autorun record.
			newAutorun := stringToAutorun("startup", startupPath, filePath, false, "")

			// Add new record to list.
			records = append(records, newAutorun)
		}
	}

	return
}

// cleanPath uses lookPath to search for the correct path to
// the executable and cleans the file path.
func cleanPath(file string) (string, error) {
	file, err := exec.LookPath(file)
	if err != nil {
		return "", err
	}
	return filepath.Clean(file), nil
}

// func windowsGetTasks() {

// }
