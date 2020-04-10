package sftpd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func NewSftpFile(file *sftp.File) *SftpFile {
	return &SftpFile{file: file}
}

func NewSftpDir(client *sftp.Client, path string) *SftpDir {
	return &SftpDir{client: client, path: path}
}

func NewSftpFs(client *sftp.Client) *sftpFs {
	return &sftpFs{client: client}
}

type SftpFile struct {
	file *sftp.File
}

func (sf *SftpFile) Close() error {
	return sf.file.Close()
}

func (sf *SftpFile) ReadAt(bs []byte, pos int64) (int, error) {
	// 设置光标位置 offset,偏移量, whence，从哪开始：0从头，1当前，2末尾
	_, err := sf.file.Seek(pos, 0)
	if err != nil {
		return 0, err
	}
	return sf.file.Read(bs)
}

func (sf *SftpFile) WriteAt(bs []byte, pos int64) (int, error) {
	// 设置光标位置 offset,偏移量, whence，从哪开始：0从头，1当前，2末尾
	_, err := sf.file.Seek(pos, 0)
	if err != nil {
		return 0, err
	}
	return sf.file.Write(bs)
}

func (sf *SftpFile) FStat() (*Attr, error) {
	var a Attr
	fi, e := sf.file.Stat()
	if e != nil {
		return nil, e
	}
	a.FillFrom(fi, 2)
	return &a, nil
}

func (sf *SftpFile) FSetStat(a *Attr) error {
	e := sf.file.Chmod(a.Mode)
	if e != nil {
		return e
	}
	sysType := runtime.GOOS
	if sysType != "windows" {	// windows 不支持 chown 操作
		e = sf.file.Chown(int(a.Uid), int(a.Gid))
	}
	return e
}

type SftpDir struct {
	client *sftp.Client
	path string
	hasRead bool
}

func (sd *SftpDir) Readdir(count int, handles Handles) ([]NamedAttr, error) {
	if sd.hasRead {
		return nil, io.EOF
	}
	sd.hasRead = true
	fis, e := sd.client.ReadDir(sd.path)
	if e != nil {
		return nil, e
	}
	rs := make([]NamedAttr, len(fis))
	for i, fi := range fis {
		rs[i].Name = fi.Name()
		rs[i].FillFrom(fi, 2)
	}
	return rs, nil
}

func (sd *SftpDir) Close() error {
	return nil
}

type sftpFs struct {
	client *sftp.Client
}

func (sfs *sftpFs) Stat(path string, isLstat bool) (*Attr, error) {
	var fi os.FileInfo
	var e error
	if isLstat {
		fi, e = sfs.client.Lstat(path)
	} else {
		fi, e = sfs.client.Stat(path)
	}

	if e != nil {
		return nil, e
	}
	var a Attr
	a.FillFrom(fi, 2)
	return &a, nil
}

func (sfs *sftpFs) OpenFile(path string, mode uint32, a *Attr) (File, error) {
	var (
		f *sftp.File
		flag int
		e error
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

	f, e = sfs.client.OpenFile(path, flag)

	if e != nil {
		return nil, e
	}
	return NewSftpFile(f), nil
}

func (sfs *sftpFs) OpenDir(path string) (Dir, error) {
	return NewSftpDir(sfs.client, path), nil
}

func (sfs *sftpFs) Remove(path string) error {
	return sfs.client.Remove(path)
}

func (sfs *sftpFs) Rename(oldName, newName string, flag uint32) error {
	return sfs.client.Rename(oldName, newName)
}

func (sfs *sftpFs) Mkdir(path string, attr *Attr) error {
	return sfs.client.Mkdir(path)
}

func (sfs *sftpFs) Rmdir(path string) error {
	return sfs.client.RemoveDirectory(path)
}

func (sfs *sftpFs) SetStat(path string, attr *Attr) error {
	e := sfs.client.Chmod(path, attr.Mode)
	if e != nil {
		return e
	}
	e = sfs.client.Chown(path, int(attr.Uid), int(attr.Gid))
	return e
}

func (sfs *sftpFs) ReadLink(path string) (string, error) {
	link, e := sfs.client.ReadLink(path)
	if e != nil {
		return "", e
	}
	return link, nil
}

func (sfs *sftpFs) CreateLink(path string, target string, flags uint32) error {
	return sfs.client.Symlink(target, path)
}

func (sfs *sftpFs) RealPath(pathX string) (string, error) {
	switch pathX {
	case "", ".":
		pathX = "/"
	default:
		pathX = path.Clean(pathX)
	}
	return pathX, nil
}

func publicKeyAuthFunc(pemBytes, keyPassword []byte) (ssh.AuthMethod, error) {
	// 通过私钥创建一个 Signer 对象，在根据 Signer 对象获取 AuthMethod 对象
	var (
		signer ssh.Signer
		err error
	)
	if string(keyPassword) == "" {
		signer, err = ssh.ParsePrivateKey(pemBytes)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, keyPassword)
	}

	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

func NewSshClientConfig(sshUser, sshPassword, sshType, sshKey, sshKeyPassword string, timeout time.Duration) (config *ssh.ClientConfig, err error) {
	// 创建 ssh 配置
	if sshUser == "" {
		return nil, errors.New("ssh_user can not be empty")
	}
	sshConfig := ssh.Config{
		// 兼容交换机等多种设备
		Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
	}
	config = &ssh.ClientConfig{
		Config: 		 sshConfig,
		Timeout:         timeout,
		User:            sshUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	switch sshType {
	case "password":
		config.Auth = []ssh.AuthMethod{ssh.Password(sshPassword)}
	case "key":
		key, err := publicKeyAuthFunc([]byte(sshKey), []byte(sshKeyPassword))
		if err != nil {
			return nil, err
		}
		config.Auth = []ssh.AuthMethod{key}
	default:
		return nil, fmt.Errorf("unknow ssh auth type: %s", sshType)
	}
	return
}

func NewSshUpstream(host, username, password string, timeout time.Duration) (*ssh.Client, *ssh.Session, error) {
	// 连接 ssh
	clientConfig, err := NewSshClientConfig(username, password, "password", "", "", timeout)
	if err != nil {
		return nil, nil, err
	}

	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}

	return client, session, nil
}