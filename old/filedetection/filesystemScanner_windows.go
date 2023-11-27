package filedetection

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gookit/color"

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
		color.Info.Print("[INFO] D-Eyes FileScan scanning: ")
		fmt.Println(file.Path())

		switch ext := strings.ToLower(filepath.Ext(file.Path())); ext {
		case ".yar":
			continue
		case ".zip", ".tar.gz", ".rar", ".7z", ".gzp", ".bzp2", ".tar", ".gz", ".iso", ".vmem", ".vhd", ".qcow2", ".vmdk":
			continue
		default:
			matches, err := s.scanner.ScanFile(file.Path())
			if err != nil {
				continue
			}
			if len(matches) != 0 {
				data := matches[0].Metas[0]
				dataType, _ := json.Marshal(data)
				dataString := string(dataType)
				meta := strings.Split(dataString, ":")[2]
				metaTmp := strings.Trim(meta, "\"}")
				resTmp := output.Result{Risk: metaTmp, RiskPath: file.Path()}
				*r = append(*r, resTmp)
			}
		}
	}
}
