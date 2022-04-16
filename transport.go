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

type Option func(*Transport) error

// WithEarlyDataHandler specifies a handler for early data sent by the initiator.
// If the error returned is non-nil, the handshake is aborted.
func WithEarlyDataHandler(h func([]byte) error) Option {
	return func(t *Transport) error {
		t.earlyDataHandler = h
		return nil
	}
}

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureConn
type Transport struct {
	localID    peer.ID
	privateKey crypto.PrivKey

	earlyDataHandler func([]byte) error
}

// New creates a new Noise transport using the given private key as its
// libp2p identity key.
func New(privkey crypto.PrivKey, opts ...Option) (*Transport, error) {
	localID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	t := &Transport{
		localID:    localID,
		privateKey: privkey,
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// SecureInbound runs the Noise handshake as the responder.
// If p is empty, connections from any peer are accepted.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, p, false, nil)
}

// SecureOutbound runs the Noise handshake as the initiator.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, p, true, nil)
}

// SecureOutboundWithEarlyData runs the Noise handshake as the initiator.
// earlyData is sent (unencrypted!) along with the first handshake message.
func (t *Transport) SecureOutboundWithEarlyData(ctx context.Context, insecure net.Conn, p peer.ID, earlyData []byte) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, p, true, earlyData)
}
