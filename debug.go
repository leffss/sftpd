// +build debug

// go build -tags "debug" main.go 时才会编译
package sftpd

import (
	"log"
)

var debug func(...interface{}) = log.Println
var debugf func(string, ...interface{}) = log.Printf