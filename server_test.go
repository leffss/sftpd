package sftpd

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	client "github.com/pkg/sftp"
	"github.com/taruti/sshutil"
	"golang.org/x/crypto/ssh"
)

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var testUser = "test"
var testPass = func() []byte {
	bs := make([]byte, 16)
	_, e := io.ReadFull(rand.Reader, bs)
	if e != nil {
		panic(e)
	}
	for i, b := range bs {
		bs[i] = alnum[int(b)%len(alnum)]
	}
	return bs
}()

var tdebug = debug
var tdebugf = debugf

func failOnErr(t *testing.T, err error, reason string) {
	if err != nil {
		t.Fatalf("%s: %v", reason, err)
	}
}

func PrintDiscardRequests(in <-chan *ssh.Request) {
	for req := range in {
		tdebug("PRINTDISC", req.Type, *req)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func TestServer(t *testing.T) {
	tdebug = t.Log
	tdebugf = t.Logf
	tdebugf("Listening on port 2022 user %s pass %s\n", testUser, testPass)

	config := &ssh.ServerConfig{
		PasswordCallback: sshutil.CreatePasswordCheck(testUser, testPass),
	}

	// Add the sshutil.RSA2048 and sshutil.Save flags if needed for the server in question...
	hkey, e := sshutil.KeyLoader{Flags: sshutil.Create}.Load()
	failOnErr(t, e, "Failed to parse host key")
	tdebugf("Public key: %s\n", sshutil.PublicKeyHash(hkey.PublicKey()))

	config.AddHostKey(hkey)

	listener, e := net.Listen("tcp", "127.0.0.1:2022")
	failOnErr(t, e, "Failed to listen")

	go ClientDo()

	//	for {
	nConn, e := listener.Accept()
	failOnErr(t, e, "Failed to accept")
	handleTestConn(nConn, config, t, EmptyFS{})
	//	}

	go ClientDo()

	//	for {
	nConn, e = listener.Accept()
	failOnErr(t, e, "Failed to accept")
	os.Mkdir("/tmp/test-sftpd", 0700)
	handleTestConn(nConn, config, t, rfs{})
	//	}
}

func handleTestConn(conn net.Conn, config *ssh.ServerConfig, t *testing.T, fs FileSystem) {
	sc, chans, reqs, e := ssh.NewServerConn(conn, config)
	failOnErr(t, e, "Failed to initiate new connection")

	tdebug("sc", sc)

	// The incoming Request channel must be serviced.
	go PrintDiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		tdebug("NEWCHANNEL", newChannel, newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			panic("could not accept channel.")
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				tdebug("REQUEST:", *req)
				ok := false
				switch {
				case IsSftpRequest(req):
					ok = true
					go func() { tdebug(ServeChannel(channel, fs)) }()
				}
				req.Reply(ok, nil)
			}
		}(requests)

	}
}

func ClientDo() {
	e := clientDo()
	if e != nil {
		tdebug("CLIENT ERROR", e)
	}
}
func clientDo() error {
	var cc ssh.ClientConfig
	cc.User = string(testUser)
	cc.Auth = append(cc.Auth, ssh.Password(string(testPass)))
	// Use this only for localhost testing.
	cc.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	conn, e := ssh.Dial("tcp4", "127.0.0.1:2022", &cc)
	if e != nil {
		return e
	}
	defer conn.Close()
	cl, e := client.NewClient(conn)
	if e != nil {
		return e
	}
	cl.Mkdir("/D")
	cl.Chmod("/D", 0700)
	cl.Remove("/D")
	rs, e := cl.ReadDir("/")
	if e != nil {
		return e
	}
	tdebug(rs)
	return nil
}

func TestRandomInput(t *testing.T) {
	fs := EmptyFS{}
	rd := &fakeRandChannel{}
	for i := 0; i < 10000; i++ {
		rd.rem = 5
		ServeChannel(rd, fs)
	}
	for i := 0; i < 257; i++ {
		for j := 0; j < 1000; j++ {
			rd.rem = i
			ServeChannel(rd, fs)
		}
	}
}

type fakeRandChannel struct{ rem int }

func (fr *fakeRandChannel) Read(data []byte) (int, error) {
	if len(data) > fr.rem {
		data = data[0:fr.rem]
	}
	n, e := rand.Read(data)
	fr.rem -= n
	if fr.rem <= 0 {
		fr.rem = 0
		e = io.EOF
	}
	if len(data) >= 4 && data[0]&1 == 0 {
		data[0], data[1], data[2] = 0, 0, 0
		for i := 5; len(data) >= 4+i; i += 4 {
			data[i], data[i+1], data[i+2] = 0, 0, 0
		}
	}
	return n, e
}
func (*fakeRandChannel) Write(bs []byte) (int, error) {
	tmp := make([]byte, 1)
	rand.Read(tmp)
	if tmp[0]&7 == 7 {
		return 0, errors.New("Random write error")
	}
	return len(bs), nil
}
func (*fakeRandChannel) Close() error      { return nil }
func (*fakeRandChannel) CloseWrite() error { return nil }
func (*fakeRandChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}
func (fr *fakeRandChannel) Stderr() io.ReadWriter { return fr }

type rfile struct {
	EmptyFile
	f *os.File
}

func (rf rfile) Close() error                             { return rf.f.Close() }
func (rf rfile) ReadAt(bs []byte, pos int64) (int, error) { return rf.f.ReadAt(bs, pos) }

type rfs struct {
	EmptyFS
}

type rdir struct {
	d *os.File
}

func (d rdir) Readdir(count int, handles Handles) ([]NamedAttr, error) {
	fis, e := d.d.Readdir(count)
	if e != nil {
		return nil, e
	}
	nas := make([]NamedAttr, len(fis))
	for i, fi := range fis {
		nas[i].Name = fi.Name()
		nas[i].FillFrom(fi, 0)
	}
	return nas, nil
}
func (d rdir) Close() error {
	return d.d.Close()
}

// Warning:
// Use your own path mangling functionality in production code.
// This can be quite non-trivial depending on the operating system.
// The code below is not sufficient for production servers.
func rfsMangle(path string) (string, error) {
	if strings.Contains(path, "..") {
		return "<invalid>", errors.New("Invalid path")
	}
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	path = "/tmp/test-sftpd/" + path
	tdebug("MANGLE -> " + path)
	return path, nil
}

func (fs rfs) OpenDir(path string) (Dir, error) {
	p, e := rfsMangle(path)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	return rdir{f}, nil
}

func (fs rfs) OpenFile(path string, mode uint32, a *Attr) (File, error) {
	p, e := rfsMangle(path)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	return rfile{f: f}, nil
}

func (fs rfs) Stat(name string, islstat bool) (*Attr, error) {
	p, e := rfsMangle(name)
	if e != nil {
		return nil, e
	}
	var fi os.FileInfo
	if islstat {
		fi, e = os.Lstat(p)
	} else {
		fi, e = os.Stat(p)
	}
	if e != nil {
		return nil, e
	}
	var a Attr
	a.FillFrom(fi, 0)

	return &a, nil
}
