package main

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSendAndReceive(t *testing.T) {
	listener, err := net.Listen("tcp", listenAddr)
	require.NoError(t, err, "net.Listen")
	tcpListener, ok := listener.(*net.TCPListener)
	require.NoError(t, err, "listener not a TCPListener")
	defer tcpListener.Close()

	go func() {
		conn, err := tcpListener.AcceptTCP()
		require.NoError(t, err, "listener.Accept")
		defer conn.Close()
		err = handleSend(conn, bytes.NewBufferString("my-test-string"), "test-password")
		require.NoError(t, err, "handleSend")
	}()

	outBuf, errBuf := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	addr, ok := tcpListener.Addr().(*net.TCPAddr)
	require.True(t, ok, "listener addr not a TCP Addr")
	err = receiveFrom(context.TODO(), addr.String(), "test-password", outBuf, errBuf)
	require.NoError(t, err, "receiveFrom")
	require.Equal(t, "my-test-string", outBuf.String(), "outBuf")
	require.Empty(t, errBuf.String(), "errBuf")
}

func TestWrongPassword(t *testing.T) {
	listener, err := net.Listen("tcp", listenAddr)
	require.NoError(t, err, "net.Listen")
	tcpListener, ok := listener.(*net.TCPListener)
	require.NoError(t, err, "listener not a TCPListener")
	defer tcpListener.Close()

	go func() {
		conn, err := tcpListener.AcceptTCP()
		require.NoError(t, err, "listener.Accept")
		defer conn.Close()
		err = handleSend(conn, bytes.NewBufferString("my-test-string"), "test-password")
		require.EqualError(t, err, ErrWrongPassword.Error(), "handleSend")
	}()

	outBuf, errBuf := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	addr, ok := tcpListener.Addr().(*net.TCPAddr)
	require.True(t, ok, "listener addr not a TCP Addr")
	err = receiveFrom(context.TODO(), addr.String(), "not-the-test-password", outBuf, errBuf)
	require.EqualError(t, err, ErrWrongPassword.Error(), "handleSend")
	require.Empty(t, outBuf.String(), "outBuf")
	require.Empty(t, errBuf.String(), "errBuf")
}
