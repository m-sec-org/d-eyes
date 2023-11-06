package filedetection

import (
	"context"
	"fmt"
	"sync"

	"github.com/hillu/go-yara/v4"

	"d-eyes/output"
	"d-eyes/yaraobj"
)

func StringSlice(name string) []string {
	return nil
}

var sum = 0

func StartFileScan(path string, rules *yara.Rules, thread int, r *[]output.Result) int {

	iteratorCtx := context.Background()
	var pathIterator Iterator

	fileExtensions := StringSlice("")

	pIt, err := IteratePath(iteratorCtx, path, fileExtensions)

	if err != nil {
		fmt.Printf("- %s ERROR: could not intialize scanner for path, reason: %v", path, err)
	}
	pathIterator = Concurrent(pathIterator, pIt)
	fmt.Printf("- %s\n", path)

	if pathIterator != nil {
		defer pathIterator.Close()
		yaraScanner, err := yaraobj.NewYaraScanner(rules)
		if err != nil {
			fmt.Println("NewYaraScanner goes error !!!")
		}

		fsScanner := NewFSScanner(yaraScanner)

		wg := &sync.WaitGroup{}
		wg.Add(thread)

		for i := 0; i < thread; i++ {
			go fsScanner.Scan(pathIterator, wg, &sum, r)
		}
		wg.Wait()
	}
	return sum

}
