package main

import (
	"net"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func GetFdFromListener(l net.Listener) int {
	v := reflect.Indirect(reflect.ValueOf(l))
	netFD := reflect.Indirect(v.FieldByName("fd"))
	pfd := netFD.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

func getListenConfig(prog *ebpf.Program, option string) net.ListenConfig {
	// set socket option SO_REUSEPORT to let multiple processes listen on the same port
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)

				if option == "main" {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD()); err != nil {
						opErr = err
					}
				}
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	return lc
}
