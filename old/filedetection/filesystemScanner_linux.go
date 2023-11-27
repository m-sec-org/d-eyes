package filedetection

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hillu/go-yara/v4"

	"d-eyes/output"
	"d-eyes/yaraobj"
)

type FSScanner struct {
	scanner *yaraobj.YaraScanner
}

func NewFSScanner(scanner *yaraobj.YaraScanner) *FSScanner {
	return &FSScanner{
		scanner: scanner,
	}
}

type FSScanProgress struct {
	File    File
	Matches yara.MatchRules
	Error   error
}

func (s *FSScanner) Scan(it Iterator, wg *sync.WaitGroup, sum *int, r *[]output.Result) {
	defer wg.Done()
	for {
		file, err := it.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			continue
		}
		*sum++
		switch ext := strings.ToLower(filepath.Ext(file.Path())); ext {
		case ".yar":
			continue
		case ".zip", ".tar.gz", ".rar", ".7z", ".gzp", ".bzp2", ".tar", ".gz", ".iso", ".vmem", ".vhd", ".qcow2", ".vmdk":
			continue
		default:
			matches, err := s.scanner.ScanFile(file.Path())
			if err != nil {
				//fmt.Println("The matches of ScanFile function goes wrong!!! ")
				//fmt.Println("err is ",err,"   file is ",file.Path())
				//fmt.Println("-----------------------------------------------")
				//return nil
			}

			if len(matches) != 0 {

				data := matches[0].Metas[0]
				dataType, _ := json.Marshal(data)
				dataString := string(dataType)
				meta := strings.Split(dataString, ":")[2]
				metaTmp := strings.Trim(meta, "\"}")
				resTmp := output.Result{metaTmp, file.Path()}
				*r = append(*r, resTmp)
			}
		}
	}
}
