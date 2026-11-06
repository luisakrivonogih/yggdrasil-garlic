//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"syscall"
)

// chownLike gives path the owner and group of the file described by like,
// best effort (e.g. root:yggdrasil for the packaged config).
func chownLike(path string, like os.FileInfo) {
	if st, ok := like.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
