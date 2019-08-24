package noise

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

const ID = "/noise/0.0.1"

var _ sec.SecureTransport = &Transport{}

type Transport struct {
	LocalID             peer.ID
	PrivateKey          crypto.PrivKey
	NoisePipesSupport   bool
	NoiseStaticKeyCache map[peer.ID]([32]byte)
}

// SecureInbound runs noise handshake as the responder
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, insecure, "", t.NoiseStaticKeyCache, t.NoisePipesSupport, false)
	if err != nil {
		return s, err
	}

	t.NoiseStaticKeyCache = s.NoiseStaticKeyCache()
	return s, nil
}

// SecureOutbound runs noise handshake as the initiator
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, insecure, p, t.NoiseStaticKeyCache, t.NoisePipesSupport, true)
	if err != nil {
		return s, err
	}

	t.NoiseStaticKeyCache = s.NoiseStaticKeyCache()
	return s, nil
}
