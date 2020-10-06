package noise

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/poly1305"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"

	crypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"

	"github.com/stretchr/testify/require"
)

func newTestTransport(t *testing.T, typ, bits int) *Transport {
	priv, pub, err := crypto.GenerateKeyPair(typ, bits)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &Transport{
		localID:    id,
		privateKey: priv,
	}
}

// Create a new pair of connected TCP sockets.
func newConnPair(t *testing.T) (net.Conn, net.Conn) {
	lstnr, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
		return nil, nil
	}

	var clientErr error
	var client net.Conn
	addr := lstnr.Addr()
	done := make(chan struct{})

	go func() {
		defer close(done)
		client, clientErr = net.Dial(addr.Network(), addr.String())
	}()

	server, err := lstnr.Accept()
	<-done

	lstnr.Close()

	if err != nil {
		t.Fatalf("Failed to accept: %v", err)
	}

	if clientErr != nil {
		t.Fatalf("Failed to connect: %v", clientErr)
	}

	return client, server
}

func connect(t *testing.T, initTransport, respTransport *Transport) (*secureSession, *secureSession) {
	init, resp := newConnPair(t)

	var initConn sec.SecureConn
	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		initConn, initErr = initTransport.SecureOutbound(context.TODO(), init, respTransport.localID)
	}()

	respConn, respErr := respTransport.SecureInbound(context.TODO(), resp)
	<-done

	if initErr != nil {
		t.Fatal(initErr)
	}

	if respErr != nil {
		t.Fatal(respErr)
	}

	return initConn.(*secureSession), respConn.(*secureSession)
}

func TestDeadlines(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	init, resp := newConnPair(t)
	defer init.Close()
	defer resp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := initTransport.SecureOutbound(ctx, init, respTransport.localID)
	if err == nil {
		t.Fatalf("expected i/o timeout err; got: %s", err)
	}

	var neterr net.Error
	if ok := errors.As(err, &neterr); !ok || !neterr.Timeout() {
		t.Fatalf("expected i/o timeout err; got: %s", err)
	}
}

func TestIDs(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	if initConn.LocalPeer() != initTransport.localID {
		t.Fatal("Initiator Local Peer ID mismatch.")
	}

	if respConn.RemotePeer() != initTransport.localID {
		t.Fatal("Responder Remote Peer ID mismatch.")
	}

	if initConn.LocalPeer() != respConn.RemotePeer() {
		t.Fatal("Responder Local Peer ID mismatch.")
	}

	// TODO: check after stage 0 of handshake if updated
	if initConn.RemotePeer() != respTransport.localID {
		t.Errorf("Initiator Remote Peer ID mismatch. expected %x got %x", respTransport.localID, initConn.RemotePeer())
	}
}

func TestKeys(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	sk := respConn.LocalPrivateKey()
	pk := sk.GetPublic()

	if !sk.Equals(respTransport.privateKey) {
		t.Error("Private key Mismatch.")
	}

	if !pk.Equals(initConn.RemotePublicKey()) {
		t.Errorf("Public key mismatch. expected %x got %x", pk, initConn.RemotePublicKey())
	}
}

func TestPeerIDMismatchFailsHandshake(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)
	init, resp := newConnPair(t)

	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, initErr = initTransport.SecureOutbound(context.TODO(), init, "a-random-peer-id")
	}()

	_, _ = respTransport.SecureInbound(context.TODO(), resp)
	<-done

	if initErr == nil {
		t.Fatal("expected initiator to fail with peer ID mismatch error")
	}
}

func makeLargePlaintext(size int) []byte {
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}

func TestLargePayloads(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	// enough to require a couple Noise messages, with a size that
	// isn't a neat multiple of Noise message size, just in case
	size := 100000

	before := makeLargePlaintext(size)
	_, err := initConn.Write(before)
	if err != nil {
		t.Fatal(err)
	}

	after := make([]byte, len(before))
	afterLen, err := io.ReadFull(respConn, after)
	if err != nil {
		t.Fatal(err)
	}

	if len(before) != afterLen {
		t.Errorf("expected to read same amount of data as written. written=%d read=%d", len(before), afterLen)
	}
	if !bytes.Equal(before, after) {
		t.Error("Message mismatch.")
	}
}

// Tests XX handshake
func TestHandshakeXX(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	before := []byte("hello world")
	_, err := initConn.Write(before)
	if err != nil {
		t.Fatal(err)
	}

	after := make([]byte, len(before))
	_, err = respConn.Read(after)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(before, after) {
		t.Errorf("Message mismatch. %v != %v", before, after)
	}
}

func TestBufferEqEncPayload(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	before := []byte("hello world")
	_, err := initConn.Write(before)
	require.NoError(t, err)

	after := make([]byte, len(before)+poly1305.TagSize)
	afterLen, err := respConn.Read(after)
	require.NoError(t, err)

	require.Equal(t, len(before), afterLen)
	require.Equal(t, before, after[:len(before)])
}

func TestBufferEqDecryptedPayload(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	before := []byte("hello world")
	_, err := initConn.Write(before)
	require.NoError(t, err)

	after := make([]byte, len(before)+1)
	afterLen, err := respConn.Read(after)
	require.NoError(t, err)

	require.Equal(t, len(before), afterLen)
	require.Equal(t, before, after[:len(before)])
}

func TestReadUnencryptedFails(t *testing.T) {
	// case1 buffer > len(msg)
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	before := []byte("hello world")
	msg := make([]byte, len(before)+LengthPrefixLength)
	binary.BigEndian.PutUint16(msg, uint16(len(before)))
	copy(msg[LengthPrefixLength:], before)
	n, err := initConn.insecureConn.Write(msg)
	require.NoError(t, err)
	require.Equal(t, len(msg), n)

	after := make([]byte, len(msg)+1)
	afterLen, err := respConn.Read(after)
	require.Error(t, err)
	require.Equal(t, 0, afterLen)

	// case2: buffer < len(msg)
	initTransport = newTestTransport(t, crypto.Ed25519, 2048)
	respTransport = newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn = connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	before = []byte("hello world")
	msg = make([]byte, len(before)+LengthPrefixLength)
	binary.BigEndian.PutUint16(msg, uint16(len(before)))
	copy(msg[LengthPrefixLength:], before)
	n, err = initConn.insecureConn.Write(msg)
	require.NoError(t, err)
	require.Equal(t, len(msg), n)

	after = make([]byte, 1)
	afterLen, err = respConn.Read(after)
	require.Error(t, err)
	require.Equal(t, 0, afterLen)
}
