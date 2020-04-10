package sftpd

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/taruti/binp"
	"github.com/taruti/bytepool"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// 前 4 字节表示数据包长度，后 4 字节转成 string 是 sftp
var sftpSubSystem = []byte{0, 0, 0, 4, 115, 102, 116, 112}

func isGbk(data []byte) bool {
	length := len(data)
	var i = 0
	for i < length {
		if data[i] <= 0xff {
			//编码小于等于127,只有一个字节的编码，兼容ASCII吗
			i++
			continue
		} else {
			//大于127的使用双字节编码
			if  data[i] >= 0x81 &&
				data[i] <= 0xfe &&
				data[i + 1] >= 0x40 &&
				data[i + 1] <= 0xfe &&
				data[i + 1] != 0xf7 {
				i += 2
				continue
			} else {
				return false
			}
		}
	}
	return true
}

func preNUm(data byte) int {
	str := fmt.Sprintf("%b", data)
	var i = 0
	for i < len(str) {
		if str[i] != '1' {
			break
		}
		i++
	}
	return i
}

func isUtf8(data []byte) bool {
	for i := 0; i < len(data);  {
		if data[i] & 0x80 == 0x00 {
			// 0XXX_XXXX
			i++
			continue
		} else if num := preNUm(data[i]); num > 2 {
			// 110X_XXXX 10XX_XXXX
			// 1110_XXXX 10XX_XXXX 10XX_XXXX
			// 1111_0XXX 10XX_XXXX 10XX_XXXX 10XX_XXXX
			// 1111_10XX 10XX_XXXX 10XX_XXXX 10XX_XXXX 10XX_XXXX
			// 1111_110X 10XX_XXXX 10XX_XXXX 10XX_XXXX 10XX_XXXX 10XX_XXXX
			// preNUm() 返回首个字节的8个bits中首个0bit前面1bit的个数，该数量也是该字符所使用的字节数
			i++
			for j := 0; j < num - 1; j++ {
				//判断后面的 num - 1 个字节是不是都是10开头
				if data[i] & 0xc0 != 0x80 {
					return false
				}
				i++
			}
		} else  {
			//其他情况说明不是utf-8
			return false
		}
	}
	return true
}

func gb18030ToUtf8(gb18030 []byte) (utf8 []byte) {
	if isUtf8(gb18030) {
		return gb18030
	} else if isGbk(gb18030) {
		utf8, err := simplifiedchinese.GB18030.NewDecoder().Bytes(gb18030)
		if err == nil {
			return utf8
		}
	} else {
		return gb18030
	}
	return gb18030
}

func utf8ToGb18030(utf8 []byte) (gb18030 []byte) {
	if isUtf8(utf8) {
		gb18030, err := simplifiedchinese.GB18030.NewEncoder().Bytes(utf8)
		if err == nil {
			return gb18030
		}
	} else if isGbk(utf8) {
		return utf8
	} else {
		return utf8
	}
	return utf8
}

// IsSftpRequest checks whether a given ssh.Request is for sftp.
func IsSftpRequest(req *ssh.Request) bool {
	//or return req.Type == "subsystem" && (string(req.Payload[4:]) == "sftp")
	return req.Type == "subsystem" && bytes.Equal(sftpSubSystem, req.Payload)
}

var initReply = []byte{0, 0, 0, 5, SSH_FXP_VERSION, 0, 0, 0, 3}

// ServeChannel serves a ssh.Channel with the given FileSystem.
func ServeChannel(c ssh.Channel, fs FileSystem, sysType int) error {
	// sysType 0 服务器为 windows，1 服务器为 linux，2 后端为 sftp
	defer c.Close()
	var h Handles
	h.Init()
	defer h.CloseAll()
	brd := bufio.NewReaderSize(c, 64 * 1024)
	var e error
	var plen int
	var op byte
	var bs []byte
	var id uint32
	for {
		if e == io.EOF {
			e = writeResponse(c, id, SSH_FX_EOF, nil)
			if e != nil {
				return e
			}
		}
		_ = discard(brd, plen)
		plen, op, e = readPacketHeader(brd)
		if e != nil {
			return e
		}
		plen--
		debugf("RECEIVED SFTP REQUEST: OP=%s(%d); LEN=%d\n", SSH_FXP(op).String(), SSH_FXP(op), plen)
		if plen < 2 {
			debug("SFTP PACKET TOO SHORT")
			return errors.New("SFTP PACKET TOO SHORT")
		}

		// Feeding too large values to peek is ok, it just errors.
		bs, e = brd.Peek(plen)
		if e != nil {
			return e
		}

		p := binp.NewParser(bs)
		switch op {
		case SSH_FXP_INIT:
			e = wrc(c, initReply)
		case SSH_FXP_OPEN:
			var (
				path string
				flags uint32
				a Attr
			)
			e = parseAttr(p.B32(&id).B32String(&path).B32(&flags), &a).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			if h.Nfiles() >= maxFiles {
				_ = writeResponse(c, id, SSH_FX_PERMISSION_DENIED, errors.New("TOO MANY OPENED FILES OR PATHS"))
				continue
			}
			path = string(gb18030ToUtf8([]byte(path)))
			var f File
			f, e = fs.OpenFile(path, flags, &a)
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, e) // or SSH_FX_PERMISSION_DENIED
				continue
			}
			e = writeHandle(c, id, h.NewFile(f))
		case SSH_FXP_CLOSE:
			var handle string
			e = p.B32(&id).B32String(&handle).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			h.CloseHandle(handle)
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_READ:
			var (
				handle string
				offset uint64
				length uint32
				n int
			)
			e = p.B32(&id).B32String(&handle).B64(&offset).B32(&length).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			f := h.GetFile(handle)
			if f == nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, errors.New("NO SUCH FILE"))
				continue
			}
			if length > 64 * 1024 {
				length = 64 * 1024
			}
			bs := bytepool.Alloc(int(length))
			n, e = f.ReadAt(bs, int64(offset))
			// Handle go readers that return io.EOF and bytes at the same time.
			if e == io.EOF && n > 0 {
				e = nil
			}
			if e != nil {
				bytepool.Free(bs)
				continue
			}
			bs = bs[0:n]
			e = wrc(c, binp.Out().B32(1+4+4+uint32(len(bs))).Byte(SSH_FXP_DATA).B32(id).B32(uint32(len(bs))).Out())
			if e == nil {
				e = wrc(c, bs)
			}
			bytepool.Free(bs)
		case SSH_FXP_WRITE:
			var (
				handle string
				offset uint64
				length uint32
			)
			p.B32(&id).B32String(&handle).B64(&offset).B32(&length)
			f := h.GetFile(handle)
			if f == nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, errors.New("NO SUCH FILE"))
				continue
			}
			var bs []byte
			e = p.NBytesPeek(int(length), &bs).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			_, e = f.WriteAt(bs, int64(offset))
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_LSTAT, SSH_FXP_STAT:
			var (
				path string
				a *Attr
			)
			e = p.B32(&id).B32String(&path).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}

			// 客户端发过来的路径 gb18030 转换为 utf-8
			path = string(gb18030ToUtf8([]byte(path)))
			a, e = fs.Stat(path, op == SSH_FXP_LSTAT)
			e = writeAttr(c, id, a, e)
		case SSH_FXP_FSTAT:
			var (
				handle string
				a *Attr
			)
			e = p.B32(&id).B32String(&handle).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			f := h.GetFile(handle)
			if f == nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, errors.New("NO SUCH FILE"))
				continue
			}
			a, e = f.FStat()
			e = writeAttr(c, id, a, e)
		case SSH_FXP_SETSTAT:
			var (
				path string
				a Attr
			)
			e = parseAttr(p.B32(&id).B32String(&path), &a).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			e = fs.SetStat(path, &a)
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_FSETSTAT:
			var (
				handle string
				a Attr
			)
			e = parseAttr(p.B32(&id).B32String(&handle), &a).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			f := h.GetFile(handle)
			if f == nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, errors.New("NO SUCH FILE"))
				continue
			}
			e = f.FSetStat(&a)
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_OPENDIR:
			var (
				path string
				dh Dir
			)
			e = p.B32(&id).B32String(&path).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			dh, e = fs.OpenDir(path)
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, errors.New("NO SUCH FILE"))
				continue
			}
			e = writeHandle(c, id, h.NewDir(dh))
		case SSH_FXP_READDIR:
			var handle string
			e = p.B32(&id).B32String(&handle).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			f := h.GetDir(handle)
			if f == nil {
				_ = writeResponse(c, id, SSH_FX_NO_SUCH_FILE, errors.New("NO SUCH FILE"))
				continue
			}
			var fis []NamedAttr
			fis, e = f.Readdir(1024, h)
			if e == io.EOF {
				e = nil
				_ = writeResponse(c, id, SSH_FX_EOF, nil)
				h.CloseHandle(handle)
				continue
			}
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_FAILURE, e)
				continue
			}
			var l binp.Len
			o := binp.Out().LenB32(&l).LenStart(&l).Byte(SSH_FXP_NAME).B32(id).B32(uint32(len(fis)))
			for _, fi := range fis {
				n := fi.Name

				// 文件名由 utf-8 转换为 gbk 在发送到客户端
				n = string(utf8ToGb18030([]byte(n)))

				// sftp 协议标准有很多版本 https://wiki.filezilla-project.org/SFTP_specifications
				// 一般 openssh 使用的是 https://filezilla-project.org/specs/draft-ietf-secsh-filexfer-02.txt
				// sftp ssh_FXP_NAME 协议中没有规定 longname 格式, 一般类似就是类 unix 系统下使用 ls -l 的结果

				o.B32String(n).B32String(readdirLongName(&fi, sysType)).B32(fi.Flags)

				if fi.Flags & ATTR_SIZE != 0 {
					o.B64(fi.Size)
				}
				if fi.Flags & ATTR_UIDGID != 0 {
					o.B32(fi.Uid).B32(fi.Gid)
				}
				if fi.Flags & ATTR_MODE != 0 {
					o.B32(fileModeToSftp(fi.Mode))
				}
				if fi.Flags & ATTR_TIME != 0 {
					outTimes(o, &fi.Attr)
				}
			}
			o.LenDone(&l)
			e = wrc(c, o.Out())
		case SSH_FXP_REMOVE:
			var path string
			e = p.B32(&id).B32String(&path).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			e = fs.Remove(path)
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_MKDIR:
			var (
				path string
				a Attr
			)
			p = p.B32(&id).B32String(&path)
			e = parseAttr(p, &a).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			e = fs.Mkdir(path, &a)
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_RMDIR:
			var path string
			e = p.B32(&id).B32String(&path).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			e = fs.Rmdir(path)
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_REALPATH:
			var path, newpath string
			e = p.B32(&id).B32String(&path).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			newpath, e = fs.RealPath(path)
			newpath = string(utf8ToGb18030([]byte(newpath)))
			e = writeNameOnly(c, id, newpath, e)
		case SSH_FXP_RENAME:
			var oldName, newName string
			var flags uint32
			_ = p.B32(&id).B32String(&oldName).B32String(&newName).B32(&flags).End()
			//if e != nil {
			//	_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
			//	return e
			//}
			oldName = string(gb18030ToUtf8([]byte(oldName)))
			newName = string(gb18030ToUtf8([]byte(newName)))
			e = fs.Rename(oldName, newName, flags)
			if e != nil {
				e = writeResponse(c, id, SSH_FX_FAILURE, e)
			}
			e = writeResponse(c, id, SSH_FX_OK, nil)
		case SSH_FXP_READLINK:
			var path string
			e = p.B32(&id).B32String(&path).End()
			if e != nil {
				_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, e)
				return e
			}
			path = string(gb18030ToUtf8([]byte(path)))
			rpath, e := fs.ReadLink(path)
			rpath = string(utf8ToGb18030([]byte(rpath)))
			e = writeNameOnly(c, id, rpath, e)
		case SSH_FXP_SYMLINK:
			p.B32(&id)
			e = writeResponse(c, id, SSH_FX_OP_UNSUPPORTED, errors.New("UNSUPPORTED SSH_FXP_SYMLINK"))
		case SSH_FXP_EXTENDED:
			var (
				extendName string
				vendorName string
				productName string
				productVersion string
				productBuildNumber uint64
			)
			p.B32(&id).B32String(&extendName).B32String(&vendorName).B32String(&productName).B32String(&productVersion).B64(&productBuildNumber)
			if extendName == "vendor-id" {
				debugf("CLIENT INFO: %s %s %s %d", vendorName, productName, productVersion, productBuildNumber)
				e = writeResponse(c, id, SSH_FX_OK, nil)
			} else {
				e = writeResponse(c, id, SSH_FX_OP_UNSUPPORTED, errors.New(fmt.Sprintf("UNSUPPORTED SSH_FXP_EXTENDED TYPE: %s", extendName)))
			}
		default:
			_ = writeResponse(c, id, SSH_FX_BAD_MESSAGE, errors.New("SSH_FX_BAD_MESSAGE"))
			return e
		}
		if e != nil {
			return e
		}
	}
}

const maxFiles = 0x100

func readPacketHeader(rd *bufio.Reader) (int, byte, error) {
	bs := make([]byte, 5)
	_, e := io.ReadFull(rd, bs)
	if e != nil {
		return 0, 0, e
	}
	return int(binary.BigEndian.Uint32(bs)), bs[4], nil
}

func parseAttr(p *binp.Parser, a *Attr) *binp.Parser {
	p = p.B32(&a.Flags)
	if a.Flags & SSH_FILEXFER_ATTR_SIZE != 0 {
		p = p.B64(&a.Size)
	}
	if a.Flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
		p = p.B32(&a.Uid).B32(&a.Gid)
	}
	if a.Flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
		var mode uint32
		p = p.B32(&mode)
		a.Mode = sftpToFileMode(mode)
	}
	if a.Flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
		p = inTimes(p, a)
	}
	if a.Flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
		var count uint32
		p = p.B32(&count)
		if count > 0xFF {
			return nil
		}
		ss := make([]string, 2*int(count))
		for i := 0; i < int(count); i++ {
			var k, v string
			p = p.B32String(&k).B32String(&v)
			ss[2*i+0] = k
			ss[2*i+1] = v
		}
		a.Extended = ss
	}
	return p
}

func writeAttr(c ssh.Channel, id uint32, a *Attr, e error) error {
	if e != nil {
		return writeResponse(c, id, SSH_FX_FAILURE, e)
	}
	var l binp.Len
	o := binp.Out().LenB32(&l).LenStart(&l).Byte(SSH_FXP_ATTRS).B32(id).B32(a.Flags)
	if a.Flags & SSH_FILEXFER_ATTR_SIZE != 0 {
		o = o.B64(a.Size)
	}
	if a.Flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
		o = o.B32(a.Uid).B32(a.Gid)
	}
	if a.Flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
		o = o.B32(fileModeToSftp(a.Mode))
	}
	if a.Flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
		outTimes(o, a)
	}
	if a.Flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
		count := uint32(len(a.Extended) / 2)
		o = o.B32(count)
		for _, s := range a.Extended {
			o = o.B32String(s)
		}
	}
	o.LenDone(&l)
	return wrc(c, o.Out())
}

func writeNameOnly(c ssh.Channel, id uint32, path string, e error) error {
	if e != nil {
		return writeResponse(c, id, SSH_FX_FAILURE, e)
	}
	var l binp.Len
	o := binp.Out().LenB32(&l).LenStart(&l).Byte(SSH_FXP_NAME).B32(id).B32(1)
	o.B32String(path).B32String(path).B32(0)
	o.LenDone(&l)
	return wrc(c, o.Out())
}

func writeResponse(c ssh.Channel, id uint32, code SSH_FX, err error) error {
	tmpl := []byte{0, 0, 0, 1 + 4 + 4 + 4 + 4, SSH_FXP_STATUS, 0, 0, 0, 0, 0, 0, 0, SSH_FX_OK, 0, 0, 0, 0, 0, 0, 0, 0}
	bs := make([]byte, len(tmpl))
	copy(bs, tmpl)
	binary.BigEndian.PutUint32(bs[5:], id)
	bs[12] = byte(code)
	if err != nil {
		debugf("SENDING SFTP RESPONSE: SP=%s(%d); ERR: %s\n", code.String(), code, err.Error())
	} else {
		debugf("SENDING SFTP RESPONSE: SP=%s(%d); ERR: nil", code.String(), code)
	}
	return wrc(c, bs)
}

func writeHandle(c ssh.Channel, id uint32, handle string) error {
	return wrc(c, binp.OutCap(4+9+len(handle)).B32(uint32(9+len(handle))).B8(SSH_FXP_HANDLE).B32(id).B32String(handle).Out())
}

func wrc(c ssh.Channel, bs []byte) error {
	_, e := c.Write(bs)
	return e
}

func discard(brd *bufio.Reader, n int) error {
	if n == 0 {
		return nil
	}
	m, e := io.Copy(ioutil.Discard, &io.LimitedReader{R: brd, N: int64(n)})
	if int(m) == n && e == io.EOF {
		e = nil
	}
	return e
}

func outTimes(o *binp.Printer, a *Attr) {
	o.B32(uint32(a.ATime.Unix())).B32(uint32(a.MTime.Unix()))
}

func inTimes(p *binp.Parser, a *Attr) *binp.Parser {
	var at, mt uint32
	p = p.B32(&at).B32(&mt)
	a.ATime = time.Unix(int64(at), 0)
	a.MTime = time.Unix(int64(mt), 0)
	return p
}