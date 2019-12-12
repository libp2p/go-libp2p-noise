package noise

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"golang.org/x/crypto/curve25519"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID for noise
const ID = "/noise"

var _ sec.SecureTransport = &Transport{}

// Keypair is a noise ed25519 public-private keypair
type Keypair struct {
	public_key  [32]byte
	private_key [32]byte
}

// GenerateKeypair creates a new ed25519 keypair
func GenerateKeypair() (*Keypair, error) {
	var public_key [32]byte
	var private_key [32]byte
	c, err := rand.Read(private_key[:])
	if err != nil {
		return nil, err
	}
	if c != 32 {
		return nil, fmt.Errorf("unable to generate 32 bytes of random data, got %d", c)
	}
	curve25519.ScalarBaseMult(&public_key, &private_key)
	return &Keypair{public_key, private_key}, nil
}

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureConn
type Transport struct {
	LocalID             peer.ID
	PrivateKey          crypto.PrivKey
	NoisePipesSupport   bool
	NoiseStaticKeyCache *KeyCache
	NoiseKeypair        *Keypair
}

type transportConstructor func(crypto.PrivKey) (*Transport, error)

// Maker returns a function that will construct a new Noise transport
// using the given Options. The returned function may be provided as a libp2p.Security
// option when configuring a libp2p Host using libp2p.New, and is compatible with the
// "reflection magic" that libp2p.New uses to inject the private identity key:
//
//    host := libp2p.New(
//      libp2p.Security(noise.ID, noise.Maker()))
//
// The transport can be configured by passing in Options.
//
// To enable the Noise Pipes pattern (which can be more efficient when reconnecting
// to a known peer), pass in the UseNoisePipes Option:
//
//    Maker(UseNoisePipes)
//
// To use a specific Noise keypair, pass in the NoiseKeyPair(kp) option, where
// kp is a noise.Keypair struct. This is most useful when using Noise Pipes, whose
// efficiency gains rely on the static Noise key being known in advance. Persisting
// the Noise keypair across process restarts makes it more likely that other peers
// will be able to use the more efficient IK handshake pattern.
//
//    Maker(UseNoisePipes, NoiseKeypair(keypairLoadedFromDisk))
func Maker(options ...Option) transportConstructor {
	return func(privKey crypto.PrivKey) (*Transport, error) {
		return New(privKey, options...)
	}
}

// New creates a new Noise transport using the given private key as its
// libp2p identity key. This function may be used when you want a transport
// instance and know the libp2p Host's identity key before the Host is initialized.
// When configuring a go-libp2p Host using libp2p.New, it's simpler to use
// Maker instead, which will receive the identity key when the Host
// is initialized.
//
// New supports all the same Options as noise.Maker.
//
// To configure a go-libp2p Host to use the newly created transport, pass it into
// libp2p.New wrapped in a libp2p.Security Option. You will also need to
// make sure to set the libp2p.Identity option so that the Host uses the same
// identity key:
//
//    privkey := loadPrivateKeyFromSomewhere()
//    noiseTpt := noise.New(privkey)
//    host := libp2p.New(
//      libp2p.Identity(privkey),
//      libp2p.Security(noise.ID, noiseTpt))
func New(privkey crypto.PrivKey, options ...Option) (*Transport, error) {
	localID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	cfg := config{}
	cfg.applyOptions(options...)

	kp := cfg.NoiseKeypair
	if kp == nil {
		kp, err = GenerateKeypair()
		if err != nil {
			return nil, err
		}
	}

	// the static key cache is only useful if Noise Pipes is enabled
	var keyCache *KeyCache
	if cfg.NoisePipesSupport {
		keyCache = NewKeyCache()
	}

	return &Transport{
		LocalID:             localID,
		PrivateKey:          privkey,
		NoisePipesSupport:   cfg.NoisePipesSupport,
		NoiseKeypair:        kp,
		NoiseStaticKeyCache: keyCache,
	}, nil
}

// SecureInbound runs noise handshake as the responder
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, t.NoiseKeypair, insecure, "", t.NoiseStaticKeyCache, t.NoisePipesSupport, false)
	if err != nil {
		return s, err
	}

	t.NoiseKeypair = s.noiseKeypair
	return s, nil
}

// SecureOutbound runs noise handshake as the initiator
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	s, err := newSecureSession(ctx, t.LocalID, t.PrivateKey, t.NoiseKeypair, insecure, p, t.NoiseStaticKeyCache, t.NoisePipesSupport, true)
	if err != nil {
		return s, err
	}

	t.NoiseKeypair = s.noiseKeypair
	return s, nil
}
