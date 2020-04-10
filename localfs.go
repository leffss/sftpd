package sftpd
// 实现了一个本地可读写的文件系统 FileSystem 接口

import (
	"errors"
	"os"
	"path"
	"runtime"
	"strings"
)

var sysType = runtime.GOOS

func NewLocalFile(file *os.File) *LocalFile {
	return &LocalFile{file: file}
}

func NewLocalDir(dir *os.File) *LocalDir {
	return &LocalDir{dir: dir}
}

func NewLocalFs(root string) *LocalFs {
	return &LocalFs{root: root}
}

type LocalFile struct {
	file *os.File
}

func (rf *LocalFile) Close() error {
	return rf.file.Close()
}

func (rf *LocalFile) ReadAt(bs []byte, pos int64) (int, error) {
	return rf.file.ReadAt(bs, pos)
}

func (rf *LocalFile) WriteAt(bs []byte, pos int64) (int, error) {
	return rf.file.WriteAt(bs, pos)
}

func (rf *LocalFile) FStat() (*Attr, error) {
	var a Attr
	fi, e := rf.file.Stat()
	if e != nil {
		return nil, e
	}
	if sysType == "linux" {
		a.FillFrom(fi, 1)
	} else {
		a.FillFrom(fi, 0)
	}
	return &a, nil
}

func (rf *LocalFile) FSetStat(a *Attr) error {
	e := rf.file.Chmod(a.Mode)
	if e != nil {
		return e
	}
	if sysType != "windows" {	// windows 不支持 chown 操作
		e = rf.file.Chown(int(a.Uid), int(a.Gid))
	}
	return e
}

type LocalDir struct {
	dir *os.File
}

func (d *LocalDir) Readdir(count int, handles Handles) ([]NamedAttr, error) {
	fis, e := d.dir.Readdir(count)
	if e != nil {
		return nil, e
	}
	rs := make([]NamedAttr, len(fis))
	for i, fi := range fis {
		rs[i].Name = fi.Name()

		if sysType == "linux" {
			rs[i].FillFrom(fi, 1)
		} else {
			rs[i].FillFrom(fi, 0)
		}
	}
	return rs, nil
}

func (d *LocalDir) Close() error {
	return d.dir.Close()
}

type LocalFs struct {
	root string
}

func (fs *LocalFs) rfsMangle(path string) (string, error) {
	if strings.Contains(path, "..") {
		return "<Invalid Path>", errors.New("Invalid Path")
	}
	if len(path) > 0 || path[0] == '/' {
		if len(path) > 1 {
			path = path[1:]
		} else {
			path = ""
		}
	}

	if len(path) <= 0 {
		path = ""
	} else if len(path) == 1 {
		if path == "/" || path == "." {
			path = ""
		}
	} else {
		if path[0] == '/' {
			path = path[1:]
		}
	}

	path = fs.root + path
	return path, nil
}

func (fs *LocalFs) Stat(path string, isLstat bool) (*Attr, error) {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return nil, e
	}
	var fi os.FileInfo
	if isLstat {
		fi, e = os.Lstat(p)
	} else {
		fi, e = os.Stat(p)
	}

	if e != nil {
		return nil, e
	}
	var a Attr
	if sysType == "linux" {
		a.FillFrom(fi, 1)
	} else {
		a.FillFrom(fi, 0)
	}
	return &a, nil
}

func (fs *LocalFs) OpenFile(path string, mode uint32, a *Attr) (File, error) {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return nil, e
	}
	var (
		f *os.File
		flag int
	)
	if mode & SSH_FXF_READ != 0 {
		flag |= os.O_RDONLY
	}
	if mode & SSH_FXF_WRITE != 0 {
		flag |= os.O_WRONLY
	}
	if mode & SSH_FXF_APPEND != 0 {
		flag |= os.O_APPEND
	}
	if mode & SSH_FXF_CREAT != 0 {
		flag |= os.O_CREATE
	}
	if mode & SSH_FXF_TRUNC != 0 {
		flag |= os.O_TRUNC
	}
	if mode & SSH_FXF_EXCL != 0 {
		flag |= os.O_EXCL
	}

	f, e = os.OpenFile(p, flag, 0644)

	if e != nil {
		return nil, e
	}
	return NewLocalFile(f), nil
}

func (fs *LocalFs) OpenDir(path string) (Dir, error) {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return nil, e
	}
	d, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	return NewLocalDir(d), nil
}

func (fs *LocalFs) Remove(path string) error {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return e
	}
	e = os.Remove(p)
	return e
}

func (fs *LocalFs) Rename(oldName, newName string, flag uint32) error {
	o, e := fs.rfsMangle(oldName)
	if e != nil {
		return e
	}
	n, e := fs.rfsMangle(newName)
	if e != nil {
		return e
	}
	return os.Rename(o, n)
}

func (fs *LocalFs) Mkdir(path string, attr *Attr) error {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return e
	}
	return os.Mkdir(p, attr.Mode)
}

func (fs *LocalFs) Rmdir(path string) error {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return e
	}
	e = os.RemoveAll(p)
	return e
}

func (fs *LocalFs) SetStat(path string, attr *Attr) error {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return e
	}

	e = os.Chmod(p, attr.Mode)
	if e != nil {
		return e
	}

	// 原则上不修改时间
	//e = os.Chtimes(p, attr.ATime, attr.MTime)
	//if e != nil {
	//	return e
	//}

	if sysType != "windows" {	// windows 不支持 chown 操作
		e = os.Chown(p, int(attr.Uid), int(attr.Gid))
	}
	return e
}

func (fs *LocalFs) ReadLink(path string) (string, error) {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return "", e
	}
	link, e := os.Readlink(p)
	if e != nil {
		return "", e
	}
	return link, nil
}

func (fs *LocalFs) CreateLink(path string, target string, flags uint32) error {
	p, e := fs.rfsMangle(path)
	if e != nil {
		return e
	}
	t, e := fs.rfsMangle(target)
	if e != nil {
		return e
	}
	return os.Symlink(p, t)
}

func (fs *LocalFs) RealPath(pathX string) (string, error) {
	switch pathX {
	case "", ".":
		pathX = "/"
	default:
		pathX = path.Clean(pathX)
	}
	return pathX, nil
}