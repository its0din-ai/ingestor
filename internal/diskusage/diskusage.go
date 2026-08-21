// Package diskusage reports how much storage a directory tree uses and how
// much space remains on its filesystem, for the admin dashboard monitor.
package diskusage

import (
	"os"
	"path/filepath"
	"syscall"
)

type Info struct {
	// UploadDirBytes is the total size of all files under the upload dir.
	UploadDirBytes int64
	// UsedBytes and TotalBytes are the filesystem's total disk usage/size.
	UsedBytes  int64
	TotalBytes int64
	// FreeBytes is the space available to an unprivileged user.
	FreeBytes int64
}

// FreePercent is the share of the filesystem that is free (0-100).
func FreePercent(i Info) float64 {
	if i.TotalBytes <= 0 {
		return 0
	}
	return float64(i.FreeBytes) / float64(i.TotalBytes) * 100
}

// UploadDir returns the total size in bytes of all regular files under dir.
// A missing directory reports 0, not an error.
func UploadDir(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return total, err
}

// Filesystem reports used, total, and free bytes for the filesystem that
// contains path.
func Filesystem(path string) (used, total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	bsize := int64(st.Bsize)
	total = int64(st.Blocks) * bsize
	used = (int64(st.Blocks) - int64(st.Bfree)) * bsize
	free = int64(st.Bavail) * bsize
	return used, total, free, nil
}

// Summary gathers upload-dir usage plus the filesystem stats for the volume
// hosting that directory (falling back to the current directory if it does
// not exist yet).
func Summary(dir string) (Info, error) {
	up, err := UploadDir(dir)
	if err != nil {
		return Info{}, err
	}
	fsPath := dir
	if _, err := os.Stat(dir); err != nil {
		fsPath = "."
	}
	used, total, free, err := Filesystem(fsPath)
	if err != nil {
		return Info{}, err
	}
	return Info{
		UploadDirBytes: up,
		UsedBytes:      used,
		TotalBytes:     total,
		FreeBytes:      free,
	}, nil
}
