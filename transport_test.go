package noise

import (
	"bytes"
	"context"
	"net"
	"testing"

	crypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
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
		LocalID:    id,
		PrivateKey: priv,
	}
}

func newTestTransportPipes(t *testing.T, typ, bits int) *Transport {
	priv, pub, err := crypto.GenerateKeyPair(typ, bits)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &Transport{
		LocalID:           id,
		PrivateKey:        priv,
		NoisePipesSupport: true,
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

	var respConn sec.SecureConn
	var respErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		respConn, respErr = respTransport.SecureOutbound(context.TODO(), resp, initTransport.LocalID)
	}()

	initConn, initErr := initTransport.SecureInbound(context.TODO(), init)
	<-done

	if initErr != nil {
		t.Fatal(initErr)
	}

	if respErr != nil {
		t.Fatal(respErr)
	}

	return initConn.(*secureSession), respConn.(*secureSession)
}

func TestIDs(t *testing.T) {
	initTransport := newTestTransport(t, crypto.Ed25519, 2048)
	respTransport := newTestTransport(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	defer initConn.Close()
	defer respConn.Close()

	if initConn.LocalPeer() != initTransport.LocalID {
		t.Fatal("Initiator Local Peer ID mismatch.")
	}

	if respConn.RemotePeer() != initTransport.LocalID {
		t.Fatal("Responder Remote Peer ID mismatch.")
	}

	if initConn.LocalPeer() != respConn.RemotePeer() {
		t.Fatal("Responder Local Peer ID mismatch.")
	}

	// TODO: check after stage 0 of handshake if updated
	if initConn.RemotePeer() != respTransport.LocalID {
		t.Errorf("Initiator Remote Peer ID mismatch. expected %x got %x", respTransport.LocalID, initConn.RemotePeer())
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

	if !sk.Equals(respTransport.PrivateKey) {
		t.Error("Private key Mismatch.")
	}

	if !pk.Equals(initConn.RemotePublicKey()) {
		t.Errorf("Public key mismatch. expected %x got %x", pk, initConn.RemotePublicKey())
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

// Test noise pipes
func TestHandshakeIK(t *testing.T) {
	initTransport := newTestTransportPipes(t, crypto.Ed25519, 2048)
	respTransport := newTestTransportPipes(t, crypto.Ed25519, 2048)

	initConn, respConn := connect(t, initTransport, respTransport)
	initConn.Close()
	respConn.Close()

	initConn, respConn = connect(t, initTransport, respTransport)
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
