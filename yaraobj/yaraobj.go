package yaraobj

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hillu/go-yara/v4"
)

const RulesZIPPassword = "Spy_on_everything_!_!_!"

type YaraScanner struct {
	rules *yara.Rules
}

func NewYaraScanner(rules *yara.Rules) (*YaraScanner, error) {
	if rules == nil {
		return nil, fmt.Errorf("cannot create a yara scanner with nil rules")
	}
	return &YaraScanner{
		rules: rules,
	}, nil
}

func (s *YaraScanner) ScanFile(filename string) ([]yara.MatchRule, error) {
	_, err := os.Stat(filename)
	if err != nil {
		//fmt.Println("ScanFile function goes wrong  !!!",err)
	}

	var matches yara.MatchRules
	err = s.rules.ScanFile(filename, 0, 0, &matches)
	return matches, err
}

//----------load yara rules------------------------------------------------------------------------------------------

// load the all rules of the special directory
func LoadAllYaraRules(rulesPath string) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create yara compiler, reason: %w", err)
	}

	compileFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		file, err := os.OpenFile(path, os.O_RDONLY, 0666)
		if err != nil {
			return fmt.Errorf("could not open rules file \"%s\", reason: %w", path, err)
		}
		defer file.Close()
		err = compiler.AddFile(file, "")
		if err != nil {
			return fmt.Errorf("could not compile rules file \"%s\", reason: %w", path, err)
		}
		return nil
	}

	f, err := os.Open(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("could not read directory \"%s\", reason: %w", rulesPath, err)
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("could not read directory \"%s\", reason: %w", rulesPath, err)
	}
	for _, name := range names {
		filename := filepath.Join(rulesPath, name)
		stat, err := os.Stat(filename)
		err = compileFn(filename, stat, err)
		if err != nil {
			return nil, err
		}
	}

	return compiler.GetRules()
}

// load the single yara rule
func LoadSingleYaraRule(path string) (*yara.Rules, error) {

	//open the yara rule
	file, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open rules file \"%s\", reason: %w", path, err)
	}
	defer file.Close()

	//create yara compiler
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create yara compiler, reason: %w", err)
	}

	errRet := compiler.AddFile(file, "")
	if errRet != nil {
		return nil, fmt.Errorf("could not compile rules file \"%s\", reason: %w", path, err)
	}
	return compiler.GetRules()

}
