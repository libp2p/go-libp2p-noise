package noise

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID for noise
const ID = "/noise"

var _ sec.SecureTransport = &Transport{}

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureConn
type Transport struct {
	localID      peer.ID
	privateKey   crypto.PrivKey
	noiseKeypair *Keypair
}

// New creates a new Noise transport using the given private key as its
// libp2p identity key.
func New(privkey crypto.PrivKey) (*Transport, error) {
	localID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}

	return &Transport{
		localID:      localID,
		privateKey:   privkey,
		noiseKeypair: kp,
	}, nil
}

// SecureInbound runs noise handshake as the responder
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, "", false)
}

// SecureOutbound runs noise handshake as the initiator
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, p, true)
}
