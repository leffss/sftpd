package sftpd

import (
	"strconv"
)

type Handles struct {
	f map[string]File
	d map[string]Dir
	c int64
}

func (h *Handles) Init() {
	h.f = map[string]File{}
	h.d = map[string]Dir{}
}

func (h *Handles) CloseAll() {
	for _, x := range h.f {
		x.Close()
	}
	for _, x := range h.d {
		x.Close()
	}

	h.c = 0
}

func (h *Handles) CloseHandle(k string) {
	if k == "" {
		return
	}
	if k[0] == 'f' {
		x, ok := h.f[k]
		if ok {
			x.Close()
		}
		delete(h.f, k)
	} else if k[0] == 'd' {
		x, ok := h.d[k]
		if ok {
			x.Close()
		}
		delete(h.d, k)
	}
}

func (h *Handles) Nfiles() int {
	return len(h.f)
}

func (h *Handles) Ndir() int {
	return len(h.d)
}

func (h *Handles) NewFile(f File) string {
	h.c++
	k := "f" + strconv.FormatInt(h.c, 16)
	h.f[k] = f
	return k
}

func (h *Handles) NewDir(f Dir) string {
	h.c++
	k := "d" + strconv.FormatInt(h.c, 16)
	h.d[k] = f
	return k
}

func (h *Handles) GetFile(n string) File {
	return h.f[n]
}

func (h *Handles) GetDir(n string) Dir {
	return h.d[n]
}