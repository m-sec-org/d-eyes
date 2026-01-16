package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func EnsureDefaultConfig(path string) error {
	if path == "" {
		return nil
	}

	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("config path is a directory: %s", path)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat config: %w", err)
	}

	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return fmt.Errorf("invalid config path: %s", path)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat config: %w", err)
	}

	content, err := EncodeDefaultYAML()
	if err != nil {
		return fmt.Errorf("encode default config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "config.yaml.*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}

	_ = os.Chmod(tmpName, 0o600)

	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			return nil
		}
		if _, statErr := os.Stat(path); statErr == nil {
			return nil
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("stat config: %w", statErr)
		}
		if err := os.Rename(tmpName, path); err != nil {
			if os.IsExist(err) {
				return nil
			}
			return fmt.Errorf("install config: %w", err)
		}
	}

	syncDirBestEffort(dir)
	return nil
}

func syncDirBestEffort(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}
