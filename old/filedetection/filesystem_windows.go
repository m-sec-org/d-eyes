package filedetection

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	FilesBuffer = 8
)

//doScandir windows

func doScanDir(path string) bool {
	return true
}

var ErrSkipped = fmt.Errorf("skipped")

type nextEntry struct {
	File File
	Err  error
}

type fsIterator struct {
	root            string
	validExtensions []string

	ctx    context.Context
	cancel context.CancelFunc
	closed bool

	dirs []string
	next chan *nextEntry
}

func IteratePath(ctx context.Context, path string, validExtensions []string) (Iterator, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("path must be a directory")
	}

	for i := range validExtensions {
		validExtensions[i] = strings.ToLower(validExtensions[i])
	}

	it := &fsIterator{
		root:            path,
		validExtensions: validExtensions,
		closed:          false,
		dirs:            make([]string, 1, 16),
		next:            make(chan *nextEntry, FilesBuffer),
	}
	it.dirs[0] = path
	it.ctx, it.cancel = context.WithCancel(ctx)

	go it.dirScanner()

	return it, nil
}

func (it *fsIterator) Root() string {
	return it.root
}

func (it *fsIterator) doesExtensionMatch(path string) bool {
	if it.validExtensions == nil || len(it.validExtensions) == 0 {
		return true
	}
	_, file := filepath.Split(path)
	parts := strings.Split(file, ".")
	var ext string
	if len(parts) > 1 {
		ext = parts[len(parts)-1]
	}
	ext = strings.ToLower(ext)

	for _, vExt := range it.validExtensions {
		if ext == vExt {
			return true
		}
	}
	return false
}

func (it *fsIterator) dirScanner() {
	defer close(it.next)

	for {
		select {
		case <-it.ctx.Done():
			break
		default:
		}

		if len(it.dirs) == 0 {
			break
		}

		dir := it.dirs[0]
		it.dirs = it.dirs[1:]

		func() {
			f, err := os.Open(dir)
			if err != nil {
				it.next <- &nextEntry{
					File: NewFile(dir),
					Err:  err,
				}
				return
			}
			defer f.Close()

			for {
				contents, err := f.Readdir(1)
				if err == io.EOF {
					break
				} else if err != nil {
					it.next <- &nextEntry{
						File: NewFile(dir),
						Err:  err,
					}
					return
				}

				path := filepath.Join(dir, contents[0].Name())
				if contents[0].IsDir() {
					if doScanDir(path) {
						it.dirs = append(it.dirs, path)
					}
				} else {
					if it.doesExtensionMatch(path) {
						it.next <- &nextEntry{
							File: NewFile(path),
						}
					} else {
						it.next <- &nextEntry{
							File: NewFile(path),
							Err:  ErrSkipped,
						}
					}
				}
			}
		}()
	}
}

func (it *fsIterator) Next() (File, error) {
	if it.closed {
		return nil, io.EOF
	}

	next := <-it.next
	if next == nil {
		return nil, io.EOF
	}

	return next.File, next.Err
}

func (it *fsIterator) Close() error {
	if it.closed {
		return nil
	}

	it.closed = true
	defer it.cancel()

	return it.ctx.Err()
}

type fileListIterator struct {
	files []string
	i     int
}

func IterateFileList(files []string) Iterator {
	return &fileListIterator{
		files: files,
		i:     0,
	}
}

func (it *fileListIterator) Next() (File, error) {
	if it.i >= len(it.files) {
		return nil, io.EOF
	}

	file := NewFile(it.files[it.i])
	it.i++
	return file, nil
}

func (it *fileListIterator) Close() error {
	return nil
}
