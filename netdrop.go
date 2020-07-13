package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/grandcat/zeroconf"
	"github.com/secure-io/sio-go"
	"github.com/urfave/cli/v2"
)

var (
	// Version is the applications build version.
	Version = "unset"
)

func main() {
	app := &cli.App{
		Name:        "netdrop",
		Usage:       "share data encrypted between peers in a network",
		Description: `With netdrop you can send files or stream data from one peer to another inside a local network.  Data is encrypted on transport and there is zero configuration necessary, just share the password with the receiver.`,
		Version:     Version,
		Commands: []*cli.Command{
			{
				Name:      "send",
				Aliases:   []string{"s"},
				Action:    sendAction,
				ArgsUsage: "/path/to/file",
				Description: `send a file or a stream of data
				
EXAMPLES:

	netdrop send my-picture.png
	tar -cz /some/directory | netdrop send`,
			},
			{
				Name:    "receive",
				Aliases: []string{"r", "recv"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "output",
						Usage: "/path/to/output/file",
					},
				},
				Action:    receiveAction,
				ArgsUsage: "password",
				Description: `receive a file or folder
				
EXAMPLES:

	netdrop receive --output my-picture.png
	netdrop send | tar -xf-`,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func receiveAction(c *cli.Context) error {
	password := c.Args().First()
	filepath := c.String("output")
	if filepath == "" {
		return receive(c.Context, password, os.Stdout, os.Stderr)
	}

	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", filepath, err)
	}
	defer f.Close()
	return receive(c.Context, password, f, os.Stderr)
}

func resolveServices(ctx context.Context) ([]*zeroconf.ServiceEntry, error) {
	resolver, err := zeroconf.NewResolver()
	if err != nil {
		return nil, err
	}
	serviceCh := make(chan *zeroconf.ServiceEntry)
	err = resolver.Lookup(ctx, zeroconfInstance, zeroconfService, zeroconfDomain, serviceCh)
	if err != nil {
		return nil, err
	}

	var entries []*zeroconf.ServiceEntry
	select {
	case entry := <-serviceCh:
		entries = append(entries, entry)
	case <-time.After(500 * time.Millisecond):
		break
	}
	return entries, nil
}

func receive(ctx context.Context, password string, output, stderr io.Writer) error {
	entries, err := resolveServices(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve netdrop services: %w", err)
	}

	for _, entry := range entries {
		err = receiveFrom(ctx, fmt.Sprintf("%s:%d", entry.AddrIPv4[0].String(), entry.Port), password, output, stderr)
		if err != nil {
			if errors.Is(err, ErrWrongPassword) {
				continue
			}
			return err
		}
		return nil
	}

	return fmt.Errorf("nothing to receive")
}

func receiveFrom(ctx context.Context, addr, password string, output, stderr io.Writer) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %q failed: %w", addr, err)
	}
	defer conn.Close()
	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("password hash failed: %w", err)
	}
	n, err := conn.Write(hash)
	if err != nil {
		return fmt.Errorf("sending password hash failed: %w", err)
	}
	if n != 32 {
		return fmt.Errorf("expected 32 bytes to be send but was %d", n)
	}

	stream, err := newStreamCipher(password)
	if err != nil {
		return fmt.Errorf("stream cipher failed: %w", err)
	}
	zeroNonce := make([]byte, stream.NonceSize())
	decR := stream.DecryptReader(conn, zeroNonce, nil)

	n64, err := io.Copy(output, decR)
	if err != nil {
		if n64 == 0 {
			// EOF
			// sio intentionally hides the error cause to prevent side-channel attacks: https://github.com/secure-io/sio-go/pull/58
			return ErrWrongPassword
		}
		return fmt.Errorf("copy failed after %d bytes: %w", n64, err)
	}
	return nil
}

const (
	zeroconfService  = "_netdrop._tcp"
	zeroconfDomain   = "local."
	zeroconfInstance = "netdrop"
)

func announce(port int) (shutdown func(), err error) {
	server, err := zeroconf.Register("netdrop", zeroconfService, zeroconfDomain, port, []string{"github.com/klingtnet/netdrop server"}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to register zerconf service")
	}

	return server.Shutdown, nil
}

const listenAddr = ":0"

func sendAction(c *cli.Context) error {
	filepath := c.Args().First()
	if filepath == "" {
		inf, err := os.Stdin.Stat()
		if err != nil {
			return fmt.Errorf("could not open stdin: %w", err)
		}
		if inf.Mode()&os.ModeNamedPipe == 0 {
			return fmt.Errorf("input is not a pipe")
		}
		return send(c.Context, os.Stdin, os.Stderr)
	}
	var f *os.File
	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open %q for reading: %w", filepath, err)
	}
	defer f.Close()
	return send(c.Context, f, os.Stderr)
}

func hashPassword(password string) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(password))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func newStreamCipher(password string) (*sio.Stream, error) {
	key := make([]byte, 32)
	copy(key, []byte(password))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create 'authenticated encryption with associated data': %w", err)
	}
	return sio.NewStream(gcm, sio.BufSize), nil
}

type Error string

func (e Error) Error() string { return string(e) }

const ErrWrongPassword = Error("client sent wrong password")

func handleSend(conn *net.TCPConn, in io.Reader, password string) error {
	actualHash := make([]byte, 32)
	nR, err := conn.Read(actualHash)
	if err != nil {
		return fmt.Errorf("failed to read password hash from client connection: %w", err)
	}
	if nR != 32 {
		return fmt.Errorf("expected 32 bytes but read %d", nR)
	}

	expectedHash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	if hex.EncodeToString(expectedHash) != hex.EncodeToString(actualHash) {
		return ErrWrongPassword
	}

	stream, err := newStreamCipher(password)
	if err != nil {
		return fmt.Errorf("failed to create stream cipher: %w", err)
	}
	zeroNonce := make([]byte, stream.NonceSize())
	encW := stream.EncryptWriter(conn, zeroNonce, nil)
	defer encW.Close()

	n, err := io.Copy(encW, in)
	if err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("send nothing")
	}
	return nil
}

func send(ctx context.Context, in io.Reader, stderr io.Writer) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %w", listenAddr, err)
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("not a TCP listener: %#v", listener.Addr())
	}
	defer tcpListener.Close()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("not a TCP addr: %w", err)
	}

	shutdownFn, err := announce(addr.Port)
	if err != nil {
		return fmt.Errorf("zeroconf announcement failed: %w", err)
	}
	// TODO: catch SIGINT and clean exit
	defer shutdownFn()

	petname.NonDeterministicMode()
	password := petname.Generate(2, "-")
	fmt.Fprintln(stderr, "password:", password)

	for {
		fmt.Fprintln(stderr, "waiting for connection...")
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}

		err = handleSend(conn, in, password)
		if err != nil {
			conn.Close()
			if errors.Is(err, ErrWrongPassword) {
				fmt.Fprintf(stderr, "%q: %s\n", conn.RemoteAddr(), err.Error())
				continue
			}
			return err
		}
		// shutdown server
		err = conn.Close()
		if err != nil {
			// ErrNetClosing is not exposed: https://github.com/golang/go/issues/4373
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return nil
			}
			return fmt.Errorf("close failed: %w", err)
		}
		return nil
	}
}
