// +build windows

package sftpd

import (
	"fmt"
	"time"
)

// 另外格式化方案可以参考 github.com/pkg/sftp 中的 runLsTypeWord， runLs 函数
func readdirLongName(fi *NamedAttr, sysType int) string {
	var user, group string
	if sysType == 2 {
		user = fmt.Sprintf("%d", fi.Uid)
		group = fmt.Sprintf("%d", fi.Gid)
	} else {
		user = "-"
		group = "-"
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