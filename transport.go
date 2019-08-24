package noise

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID for noise
const ID = "/noise/0.0.1"

var _ sec.SecureTransport = &Transport{}

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureConn
type Transport struct {
	LocalID             peer.ID
	PrivateKey          crypto.PrivKey
	NoisePipesSupport   bool
	NoiseStaticKeyCache map[peer.ID]([32]byte)
	NoisePrivateKey     [32]byte
	NoisePublicKey      [32]byte
}

func NewTransport(localID peer.ID, privkey crypto.PrivKey, noisePipesSupport bool) *Transport {
	return &Transport{
		LocalID:           localID,
		PrivateKey:        privkey,
		NoisePipesSupport: noisePipesSupport,
	}
}

// SecureInbound runs noise handshake as the responder
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, t.NoisePrivateKey, insecure, "", t.NoiseStaticKeyCache, t.NoisePipesSupport, false)
	if err != nil {
		return s, err
	}

	t.NoiseStaticKeyCache = s.NoiseStaticKeyCache()
	t.NoisePrivateKey = s.NoisePrivateKey()
	t.NoisePublicKey = s.local.noiseKey
	return s, nil
}

// SecureOutbound runs noise handshake as the initiator
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, t.NoisePrivateKey, insecure, p, t.NoiseStaticKeyCache, t.NoisePipesSupport, true)
	if err != nil {
		log.Debugf("err: %s\n", err)
		return s, err
	}
	log.Debug("created secret session")
	t.NoiseStaticKeyCache = s.NoiseStaticKeyCache()
	t.NoisePrivateKey = s.NoisePrivateKey()
	t.NoisePublicKey = s.local.noiseKey
	log.Debug("Retrieved keys")
	return s, nil
}
