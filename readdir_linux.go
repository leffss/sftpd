// +build linux

package sftpd

import (
	"bytes"
	"fmt"
	"os/exec"
	"time"
)

const shellToUse = "sh"

var users map[uint32]string
var groups map[uint32]string

func init()  {
	// 所有 sftp 连接共用变量
	users = make(map[uint32]string)
	groups = make(map[uint32]string)
}

func shellout(command string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(shellToUse, "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// 另外格式化方案可以参考 github.com/pkg/sftp 中的 runLsTypeWord， runLs 函数
func readdirLongName(fi *NamedAttr, sysType int) string {
	// 执行命令很耗时，把前面的结果存 map，有则不用再去执行命令了
	// 缺点就是如果某个 uid 或者 gid 对应的用户或者组的名称变了，不能感知，问题不大
	var user, group string
	if sysType == 2 {
		user = fmt.Sprintf("%d", fi.Uid)
		group = fmt.Sprintf("%d", fi.Gid)
	} else {
		if u, ok := users[fi.Uid]; ok {
			user = u
		} else {
			user = string(fi.Uid)
			stdout, _, e := shellout(fmt.Sprintf("/usr/bin/getent passwd %d 2>/dev/null|awk -F : '{print $1}'", fi.Uid))
			if e == nil {
				if stdout != "" {
					user = stdout

				}
			}
			users[fi.Uid] = user
		}

		if g, ok := groups[fi.Gid]; ok {
			group = g
		} else {
			group = string(fi.Gid)
			stdout, _, e := shellout(fmt.Sprintf("/usr/bin/getent group %d 2>/dev/null|awk -F : '{print $1}'", fi.Gid))
			if e == nil {
				if stdout != "" {
					group = stdout
				}
			}
			groups[fi.Gid] = group
		}

		user = fmt.Sprintf("%s(%d)", user, fi.Uid)
		group = fmt.Sprintf("%s(%d)", group, fi.Gid)
	}
	return fmt.Sprintf("%s %4d %-8s %-8s %8d %12s %s",
		//fi.Mode.String(),
		fi.ModeString,
		1, // links
		user, group,
		//fi.User, fi.Group,
		fi.Size,
		readdirTimeFormat(fi.MTime),
		fi.Name,
	)
}

func readdirTimeFormat(t time.Time) string {
	// We return timestamps in UTC, should we offer a customisation point for users?
	if t.Year() == time.Now().Year() {
		return t.Format("Jan _2 15:04")
	}
	return t.Format("Jan _2  2006")
}