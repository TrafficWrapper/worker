package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func writeJSONFile(path string, value any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFile(path, raw, mode)
}

func writeFile(path string, raw []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := writeSyncClose(f, raw, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// createFileExclusive atomically publishes raw at path only if path does not
// exist yet, so concurrent bootstraps cannot overwrite each other's keys.
func createFileExclusive(path string, raw []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := writeSyncClose(f, raw, mode); err != nil {
		return err
	}
	if err := linkFile(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		// Some bind-mounted filesystems do not support hard links. A lock
		// file picks a single writer and a rename publishes the content in
		// one step, so a crash never leaves a partial file at path.
		if err := renameExclusive(tmp, path); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

// linkFile is os.Link; tests replace it to simulate filesystems without
// hard links.
var linkFile = os.Link

// staleLockAge is how old a leftover lock must be before it is broken.
const staleLockAge = 30 * time.Second

func renameExclusive(tmp, path string) error {
	lock := path + ".lock"
	for attempt := 0; attempt < 2; attempt++ {
		l, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			if info, statErr := os.Stat(lock); statErr == nil && time.Since(info.ModTime()) > staleLockAge {
				_ = os.Remove(lock)
				continue
			}
			return fmt.Errorf("%s is being written by another process", path)
		}
		if err != nil {
			return err
		}
		_ = l.Close()
		defer os.Remove(lock)
		if _, err := os.Lstat(path); err == nil {
			return os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return os.Rename(tmp, path)
	}
	return fmt.Errorf("%s: could not take the write lock", path)
}

func writeSyncClose(f *os.File, raw []byte, mode os.FileMode) error {
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
