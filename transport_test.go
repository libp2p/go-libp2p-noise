package noise

import (
	"bytes"
	"context"
	"math/rand"
	"net"
	"testing"

	//ik "github.com/libp2p/go-libp2p-noise/ik"
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
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return &Transport{
		localID:      id,
		privateKey:   priv,
		noiseKeypair: kp,
	}
}

func newTestTransportPipes(t *testing.T, typ, bits int) *Transport {
	tpt := newTestTransport(t, typ, bits)
	tpt.noisePipesSupport = true
	return tpt
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
	initDone := make(chan struct{})
	go func() {
		defer close(initDone)
		_, initErr = initTransport.SecureOutbound(context.TODO(), init, "a-random-peer-id")
	}()

	respDone := make(chan struct{})
	go func() {
		defer close(respDone)
		_, _ = respTransport.SecureInbound(context.TODO(), resp)
	}()

	select {
	case <-initDone:
	case <-respDone:
	}

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
	afterLen, err := respConn.Read(after)
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

// Test IK handshake
func TestHandshakeIK(t *testing.T) {
	initTransport := newTestTransportPipes(t, crypto.Ed25519, 2048)
	respTransport := newTestTransportPipes(t, crypto.Ed25519, 2048)

	// add responder's static key to initiator's key cache
	keycache := NewKeyCache()
	keycache.Store(respTransport.localID, respTransport.noiseKeypair.publicKey)
	initTransport.noiseStaticKeyCache = keycache

	// do IK handshake
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

	// make sure IK was actually used
	if !(initConn.ik_complete && respConn.ik_complete) {
		t.Error("Expected IK handshake to be used")
	}
}

// Test noise pipes
func TestHandshakeXXfallback(t *testing.T) {
	initTransport := newTestTransportPipes(t, crypto.Ed25519, 2048)
	respTransport := newTestTransportPipes(t, crypto.Ed25519, 2048)

	// turning on pipes causes it to default to IK, but since we haven't already
	// done a handshake, it'll fallback to XX
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

	// make sure XX was actually used
	if !(initConn.xx_complete && respConn.xx_complete) {
		t.Error("Expected XXfallback handshake to be used")
	}
}
