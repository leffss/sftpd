// +build linux

// windows 无 syscall.Stat_t
package sftpd

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/pkg/sftp"
)

type Attr struct {
	Flags        uint32
	Size         uint64
	Uid, Gid     uint32
	User, Group  string
	Mode         os.FileMode
	ModeString	 string
	ATime, MTime time.Time
	Extended     []string
}

type NamedAttr struct {
	Name string
	Attr
}

const (
	ATTR_SIZE    = SSH_FILEXFER_ATTR_SIZE
	ATTR_UIDGID  = SSH_FILEXFER_ATTR_UIDGID
	ATTR_MODE    = SSH_FILEXFER_ATTR_PERMISSIONS
	ATTR_TIME    = SSH_FILEXFER_ATTR_ACMODTIME
	MODE_REGULAR = os.FileMode(0)
	MODE_DIR     = os.ModeDir
)

type Dir interface {
	io.Closer
	Readdir(count int, handles Handles) ([]NamedAttr, error)
}

type File interface {
	io.Closer
	io.ReaderAt
	io.WriterAt
	FStat() (*Attr, error)
	FSetStat(*Attr) error
}

type FileSystem interface {
	OpenFile(name string, flags uint32, attr *Attr) (File, error)
	OpenDir(name string) (Dir, error)
	Remove(name string) error
	Rename(old string, new string, flags uint32) error
	Mkdir(name string, attr *Attr) error
	Rmdir(name string) error
	Stat(name string, islstat bool) (*Attr, error)
	SetStat(name string, attr *Attr) error
	ReadLink(path string) (string, error)
	CreateLink(path string, target string, flags uint32) error
	RealPath(path string) (string, error)
}

// FillFrom fills an Attr from a os.FileInfo
func (a *Attr) FillFrom(fi os.FileInfo, sysType int) {
	*a = Attr{}
	a.Flags = ATTR_SIZE | ATTR_MODE | ATTR_TIME | ATTR_UIDGID
	a.Size = uint64(fi.Size())
	a.Mode = fi.Mode()
	a.MTime = fi.ModTime()
	// windows 平台下无法使用 *syscall.Stat_t，需使用 *syscall.Win32FileAttributeData
	// 且 windows 平台下无 Uid 或 Gid
	if sysType == 1 {
		info := fi.Sys().(*syscall.Stat_t)
		a.Uid = info.Uid
		a.Gid = info.Gid
	} else if sysType == 2 {
		info := fi.Sys().(*sftp.FileStat)
		a.Uid = info.UID
		a.Gid = info.GID
	}
	a.ModeString = runLsTypeWord(fi)
}

// 参考 github.com/pkg/sftp 中 fromFileMode, 识别文件类型的关键函数
func fileModeToSftp(mode os.FileMode) uint32 {
	//var raw = uint32(m.Perm())
	//switch {
	//case m.IsDir():
	//	raw |= 0040000
	//case m.IsRegular():
	//	raw |= 0100000
	//}
	//return raw
	ret := uint32(0)

	if mode&os.ModeDevice != 0 {
		if mode&os.ModeCharDevice != 0 {
			ret |= syscall.S_IFCHR
		} else {
			ret |= syscall.S_IFBLK
		}
	}
	if mode&os.ModeDir != 0 {
		ret |= syscall.S_IFDIR
	}
	if mode&os.ModeSymlink != 0 {
		ret |= syscall.S_IFLNK
	}
	if mode&os.ModeNamedPipe != 0 {
		ret |= syscall.S_IFIFO
	}
	if mode&os.ModeSetgid != 0 {
		ret |= syscall.S_ISGID
	}
	if mode&os.ModeSetuid != 0 {
		ret |= syscall.S_ISUID
	}
	if mode&os.ModeSticky != 0 {
		ret |= syscall.S_ISVTX
	}
	if mode&os.ModeSocket != 0 {
		ret |= syscall.S_IFSOCK
	}

	if mode&os.ModeType == 0 {
		ret |= syscall.S_IFREG
	}
	ret |= uint32(mode & os.ModePerm)

	return ret
}

// 参考 github.com/pkg/sftp 中 toFileMode, 识别文件类型的关键函数
func sftpToFileMode(mode uint32) os.FileMode {
	//var m = os.FileMode(raw & 0777)
	//switch {
	//case raw&0040000 != 0:
	//	m |= os.ModeDir
	//case raw&0100000 != 0:
	//	// regular
	//}
	//return m

	var fm = os.FileMode(mode & 0777)
	switch mode & S_IFMT {
	case syscall.S_IFBLK:
		fm |= os.ModeDevice
	case syscall.S_IFCHR:
		fm |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		fm |= os.ModeDir
	case syscall.S_IFIFO:
		fm |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		fm |= os.ModeSymlink
	case syscall.S_IFREG:
		// nothing to do
	case syscall.S_IFSOCK:
		fm |= os.ModeSocket
	}
	if mode&syscall.S_ISGID != 0 {
		fm |= os.ModeSetgid
	}
	if mode&syscall.S_ISUID != 0 {
		fm |= os.ModeSetuid
	}
	if mode&syscall.S_ISVTX != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// 比 fi.Mode.String() 准确
func runLsTypeWord(dirent os.FileInfo) string {
	// find first character, the type char
	// b     Block special file.
	// c     Character special file.
	// d     Directory.
	// l     Symbolic link.
	// s     Socket link.
	// p     FIFO.
	// -     Regular file.
	tc := '-'
	mode := dirent.Mode()
	if (mode & os.ModeDir) != 0 {
		tc = 'd'
	} else if (mode & os.ModeDevice) != 0 {
		tc = 'b'
		if (mode & os.ModeCharDevice) != 0 {
			tc = 'c'
		}
	} else if (mode & os.ModeSymlink) != 0 {
		tc = 'l'
	} else if (mode & os.ModeSocket) != 0 {
		tc = 's'
	} else if (mode & os.ModeNamedPipe) != 0 {
		tc = 'p'
	}

	// owner
	orc := '-'
	if (mode & 0400) != 0 {
		orc = 'r'
	}
	owc := '-'
	if (mode & 0200) != 0 {
		owc = 'w'
	}
	oxc := '-'
	ox := (mode & 0100) != 0
	setuid := (mode & os.ModeSetuid) != 0
	if ox && setuid {
		oxc = 's'
	} else if setuid {
		oxc = 'S'
	} else if ox {
		oxc = 'x'
	}

	// group
	grc := '-'
	if (mode & 040) != 0 {
		grc = 'r'
	}
	gwc := '-'
	if (mode & 020) != 0 {
		gwc = 'w'
	}
	gxc := '-'
	gx := (mode & 010) != 0
	setgid := (mode & os.ModeSetgid) != 0
	if gx && setgid {
		gxc = 's'
	} else if setgid {
		gxc = 'S'
	} else if gx {
		gxc = 'x'
	}

	// all / others
	arc := '-'
	if (mode & 04) != 0 {
		arc = 'r'
	}
	awc := '-'
	if (mode & 02) != 0 {
		awc = 'w'
	}
	axc := '-'
	ax := (mode & 01) != 0
	sticky := (mode & os.ModeSticky) != 0
	if ax && sticky {
		axc = 't'
	} else if sticky {
		axc = 'T'
	} else if ax {
		axc = 'x'
	}

	return fmt.Sprintf("%c%c%c%c%c%c%c%c%c%c", tc, orc, owc, oxc, grc, gwc, gxc, arc, awc, axc)
}