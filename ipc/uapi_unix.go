//go:build linux || darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

// socketDirectory is variable because it is modified by a linker
// flag in wireguard-android.
var socketDirectory = "/var/run/wireguard"

// sockPath 获取sock文件
func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", socketDirectory, iface)
}

// 打开UAPI
func UAPIOpen(name string) (*os.File, error) {
	// 创建文件夹/var/run/wireguard
	if err := os.MkdirAll(socketDirectory, 0o755); err != nil {
		return nil, err
	}
	// 获取unix socket路径
	socketPath := sockPath(name)
	// 返回unix套接字地址
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}
	//TODO：不晓得干嘛的
	oldUmask := unix.Umask(0o077)
	defer unix.Umask(oldUmask)
	// 监听unix文件
	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		// 返回listener的文件
		return listener.File()
	}

	// 如果不能用就重试一下？先判断unix是不是已经被使用了，如果没有，则删除这个链接并重新监听
	// Test socket, if not in use cleanup and try again.
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}
