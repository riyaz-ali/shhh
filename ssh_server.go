package main

import (
	"fmt"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"strconv"
	"time"
)

// ----------
// The file defines the types and methods that runs/manages the ssh server
// ----------

const (
	// key name for tracking 'messages' channel in ssh.Context
	messageChannelName = "messages"

	// SSH request type constant for TCP/IP port forward
	tcpipForwardRequest = "tcpip-forward"

	// SSH request type constant for opening new channel
	// for incoming request on a forwarded port
	tcpipForwardIncomingConnectionRequest = "forwarded-tcpip"
)

// NewSSHServer returns a new ssh.Server instance with configured defaults
// for handling port forwarding and additional secure defaults
func NewSSHServer(addr string, options ...ssh.Option) (*ssh.Server, error) {
	server := &ssh.Server{
		Addr:         addr,
		Handler:      messageForwardingHandler(),
		PtyCallback:  noPty(),
		ConnCallback: connectionWrapper(),
		IdleTimeout:  1 * time.Minute,
		RequestHandlers: map[string]ssh.RequestHandler{
			tcpipForwardRequest: tcpipForwardRequestHandler(),
		},
	}

	for _, opt := range options {
		if err := server.SetOption(opt); err != nil {
			return nil, err
		}
	}

	return server, nil
}

// noPty returns a ssh.PtyCallback that denies any PTY allocation request
func noPty() ssh.PtyCallback {
	return func(ctx ssh.Context, pty ssh.Pty) bool {
		return false
	}
}

// connectionWrapper returns a new ssh.ConnCallback which creates a new messaging channel
// for every new SSH connection. This channel is later used to send messages to be displayed
// on the client terminal.
func connectionWrapper() ssh.ConnCallback {
	return func(ctx ssh.Context, conn net.Conn) net.Conn {
		ctx.SetValue(messageChannelName, make(chan string))
		return conn
	}
}

// messageForwardingHandler returns an ssh.Handler which reads from [messageChannelName] and writes
// messages to the client session
func messageForwardingHandler() ssh.Handler {
	return func(s ssh.Session) {
		messages, ok := s.Context().Value("messages").(chan string)
		if !ok {
			_, _ = io.WriteString(s, "internal server error\n")
			_ = s.Exit(1)
		}

		for msg := range messages {
			_, _ = io.WriteString(s, fmt.Sprintf("%s\n", msg))
		}
	}
}

// tcpipForwardRequestHandler returns an ssh.RequestHandler which handles SSH request of type "tcpip-forward"
func tcpipForwardRequestHandler() ssh.RequestHandler {
	return func(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (ok bool, payload []byte) {
		var err error

		var messages chan string
		if messages, ok = ctx.Value(messageChannelName).(chan string); !ok {
			return false, []byte("internal server error")
		}
		defer func() {
			if !ok { // close messages channel if response is !ok
				close(messages)
			}
		}()

		// get the underlying ssh connection
		sshConnection := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

		// parse the request
		var request struct {
			BindAddr string
			BindPort uint32
		}

		if err = gossh.Unmarshal(req.Payload, &request); err != nil {
			return false, []byte{}
		}

		var ln net.Listener
		if request.BindPort != 22 && request.BindPort != 80 && request.BindPort != 443 {
			addr := net.JoinHostPort(request.BindAddr, strconv.Itoa(int(request.BindPort)))
			if ln, err = net.Listen("tcp", addr); err != nil {
				return false, []byte{}
			} else {
				messages <- fmt.Sprintf("forwarding traffic from %s", ln.Addr().String())
			}
		} else {
			return false, []byte(fmt.Sprintf("forwarding %d not supported yet", request.BindPort))
		}

		// destination port could be different in case request.BindPort was '0' (zero)
		_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
		destPort, _ := strconv.Atoi(destPortStr)

		// close listener once the ssh connection is closed
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()

		go func() {
			for {
				var err error

				c, err := ln.Accept()
				if err != nil {
					messages <- "error occurred while accepting connection\n"
					break
				}
				originAddr, originPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.Atoi(originPortStr)

				var forward = struct {
					DestAddr   string
					DestPort   uint32
					OriginAddr string
					OriginPort uint32
				}{
					DestAddr: request.BindAddr, DestPort: uint32(destPort),
					OriginAddr: originAddr, OriginPort: uint32(originPort),
				}
				payload := gossh.Marshal(&forward)

				// send notification to client
				messages <- fmt.Sprintf("accepted connection from %s:%d", originAddr, originPort)

				ch, reqs, err := sshConnection.OpenChannel(tcpipForwardIncomingConnectionRequest, payload)
				if err != nil {
					messages <- "error occurred while forwarding connection"
					c.Close()
					break
				}

				go gossh.DiscardRequests(reqs)
				go func() {
					defer ch.Close()
					defer c.Close()
					_, _ = io.Copy(ch, c)
				}()
				go func() {
					defer ch.Close()
					defer c.Close()
					_, _ = io.Copy(c, ch)
				}()
			}

			close(messages) // to close the session as well
		}()

		var response = struct{ BindPort uint32 }{uint32(destPort)}
		return true, gossh.Marshal(&response)
	}
}
