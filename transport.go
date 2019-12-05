package noise

import (
	"context"
	"crypto/rand"
	"net"

	"golang.org/x/crypto/curve25519"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID for noise
const ID = "/noise/0.0.1"

var _ sec.SecureTransport = &Transport{}

// Keypair is a noise ed25519 public-private keypair
type Keypair struct {
	public_key  [32]byte
	private_key [32]byte
}

// GenerateKeypair creates a new ed25519 keypair
func GenerateKeypair() *Keypair {
	var public_key [32]byte
	var private_key [32]byte
	_, _ = rand.Read(private_key[:])
	curve25519.ScalarBaseMult(&public_key, &private_key)
	return &Keypair{public_key, private_key}
}

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureConn
type Transport struct {
	LocalID             peer.ID
	PrivateKey          crypto.PrivKey
	NoisePipesSupport   bool
	NoiseStaticKeyCache map[peer.ID]([32]byte)
	NoiseKeypair        *Keypair
}

// NewTransport creates a new noise transport and can be configured to use noise pipes and a given
// noise ed25519 keypair
func NewTransport(localID peer.ID, privkey crypto.PrivKey, noisePipesSupport bool, kp *Keypair) *Transport {
	if kp == nil {
		kp = GenerateKeypair()
	}

	return &Transport{
		LocalID:           localID,
		PrivateKey:        privkey,
		NoisePipesSupport: noisePipesSupport,
		NoiseKeypair:      kp,
	}
}

// SecureInbound runs noise handshake as the responder
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, t.NoiseKeypair, insecure, "", t.NoiseStaticKeyCache, t.NoisePipesSupport, false)
	if err != nil {
		return s, err
	}

	t.NoiseStaticKeyCache = s.NoiseStaticKeyCache()
	t.NoiseKeypair = s.noiseKeypair
	return s, nil
}

// SecureOutbound runs noise handshake as the initiator
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, t.NoiseKeypair, insecure, p, t.NoiseStaticKeyCache, t.NoisePipesSupport, true)
	if err != nil {
		return s, err
	}

	t.NoiseStaticKeyCache = s.NoiseStaticKeyCache()
	t.NoiseKeypair = s.noiseKeypair
	return s, nil
}
