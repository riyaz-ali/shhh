package main

import (
	_ "github.com/pkg/errors"
	"net"
	"strconv"
)

// ----------
// This file contains mostly helper methods that allow the SSH server to create listeners for TCP sockets
// ----------


// allowTCPForwarding returns true if the given [port] is eligible for TCP forwarding
func allowTCPForwarding(port uint32) bool {
	return (port != 22 && port != 80 && port != 443) && port > 1024 || port == 0
}

// tcpListen returns a listener which listens on the given port for incoming TCP connection
func tcpListen(addr string, port uint32) (net.Listener, error) {
	addr = net.JoinHostPort(addr, strconv.Itoa(int(port)))
	return net.Listen("tcp", addr)
}