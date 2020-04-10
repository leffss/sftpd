// +build !debug

package sftpd

func debug(...interface{})          {}
func debugf(string, ...interface{}) {}

//var debug func(...interface{}) = log.Println
//var debugf func(string, ...interface{}) = log.Printf