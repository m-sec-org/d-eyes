package filedetection

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

var globalHasher *CachingHasher

func init() {
	globalHasher = NewCachingHasher()
}

// ComputeHashes computes the md5 and sha256 hashes of a given file.
func ComputeHashes(file string) (md5sum, sha256sum string, err error) {
	return globalHasher.ComputeHashes(file)
}

type multiHash struct {
	md5sum    string
	sha256sum string
}

type CachingHasher struct {
	hashes map[string]*multiHash
	mux    *sync.RWMutex
}

func NewCachingHasher() *CachingHasher {
	return &CachingHasher{
		hashes: map[string]*multiHash{},
		mux:    &sync.RWMutex{},
	}
}

func (h *CachingHasher) readCache(file string) (*multiHash, bool) {
	h.mux.RLock()
	defer h.mux.RUnlock()

	hashes, ok := h.hashes[file]
	return hashes, ok
}

func (h *CachingHasher) writeCache(file string, hashes *multiHash) {
	h.mux.Lock()
	defer h.mux.Unlock()

	h.hashes[file] = hashes
}

// ComputeHashes computes the md5 and sha256 hashes of a given file.
func (h *CachingHasher) ComputeHashes(file string) (md5sum, sha256sum string, err error) {
	hashes, ok := h.readCache(file)
	if ok {
		return hashes.md5sum, hashes.sha256sum, nil
	}

	var f *os.File
	f, err = os.OpenFile(file, os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	defer f.Close()

	h5 := md5.New()
	h256 := sha256.New()

	teeH5 := io.TeeReader(f, h5)
	_, err = io.Copy(h256, teeH5)
	if err != nil {
		return
	}

	md5sum = hex.EncodeToString(h5.Sum(nil))
	sha256sum = hex.EncodeToString(h256.Sum(nil))

	h.writeCache(file, &multiHash{
		md5sum:    md5sum,
		sha256sum: sha256sum,
	})

	return
}
