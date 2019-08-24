package noise

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

const ID = "/noise/0.0.0"

var _ sec.SecureTransport = &Transport{}

type Transport struct {
	LocalID    peer.ID
	PrivateKey crypto.PrivKey
}

// SecureInbound runs noise handshake as the responder
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	return newSecureSession(ctx, t.LocalID, t.PrivateKey, insecure, "", false)
}

// SecureOutbound runs noise handshake as the initiator
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSecureSession(ctx, t.LocalID, t.PrivateKey, insecure, p, true)
}
