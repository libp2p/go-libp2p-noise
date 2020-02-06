package noise

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	logging "github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/libp2p/go-libp2p-noise/core"
)

const payloadSigningPrefix = "noise-libp2p-static-key:"

// Each encrypted transport message must be <= 65,535 bytes, including 16
// bytes of authentication data. To write larger plaintexts, we split them
// into fragments of maxPlaintextLength before encrypting.
const maxPlaintextLength = 65519

var log = logging.Logger("noise")

var errNoKeypair = errors.New("cannot initiate secureSession - transport has no noise keypair")

type secureSession struct {
	insecure net.Conn

	initiator bool
	prologue  []byte

	localKey   crypto.PrivKey
	localPeer  peer.ID
	remotePeer peer.ID

	local  peerInfo
	remote peerInfo

	ns *core.NoiseSession

	xx_complete bool
	ik_complete bool

	noisePipesSupport   bool
	noiseStaticKeyCache *KeyCache

	noiseKeypair *core.Keypair

	msgBuffer []byte
	readLock  sync.Mutex
	writeLock sync.Mutex
}

type peerInfo struct {
	noiseKey  [32]byte // static noise public key
	libp2pKey crypto.PubKey
}

// newSecureSession creates a noise session over the given insecure Conn, using the static
// Noise keypair and libp2p identity keypair from the given Transport.
//
// If tpt.noisePipesSupport == true, the Noise Pipes handshake protocol will be used,
// which consists of the IK and XXfallback handshake patterns. With Noise Pipes on, we first try IK,
// if that fails, move to XXfallback. With Noise Pipes off, we always do XX.
func newSecureSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*secureSession, error) {
	if tpt.noiseKeypair == nil {
		return nil, errNoKeypair
	}

	// if the transport doesn't have a key cache, we make a new one just for
	// this session. it's a bit of a waste, but saves us having to check if
	// it's nil later
	keyCache := tpt.noiseStaticKeyCache
	if keyCache == nil {
		keyCache = NewKeyCache()
	}

	localPeerInfo := peerInfo{
		noiseKey:  tpt.noiseKeypair.PubKey(),
		libp2pKey: tpt.privateKey.GetPublic(),
	}

	s := &secureSession{
		insecure:            insecure,
		initiator:           initiator,
		prologue:            []byte{},
		localKey:            tpt.privateKey,
		localPeer:           tpt.localID,
		remotePeer:          remote,
		local:               localPeerInfo,
		noisePipesSupport:   tpt.noisePipesSupport,
		noiseStaticKeyCache: keyCache,
		msgBuffer:           []byte{},
		noiseKeypair:        tpt.noiseKeypair,
	}

	err := s.runHandshake(ctx)
	return s, err
}

func (s *secureSession) NoiseStaticKeyCache() *KeyCache {
	return s.noiseStaticKeyCache
}

func (s *secureSession) NoisePublicKey() [32]byte {
	return s.noiseKeypair.PubKey()
}

func (s *secureSession) NoisePrivateKey() [32]byte {
	return s.noiseKeypair.PrivKey()
}

func (s *secureSession) LocalAddr() net.Addr {
	return s.insecure.LocalAddr()
}

func (s *secureSession) LocalPeer() peer.ID {
	return s.localPeer
}

func (s *secureSession) LocalPrivateKey() crypto.PrivKey {
	return s.localKey
}

func (s *secureSession) LocalPublicKey() crypto.PubKey {
	return s.localKey.GetPublic()
}

func (s *secureSession) Read(buf []byte) (int, error) {
	return s.readSecure(buf)
}

func (s *secureSession) RemoteAddr() net.Addr {
	return s.insecure.RemoteAddr()
}

func (s *secureSession) RemotePeer() peer.ID {
	return s.remotePeer
}

func (s *secureSession) RemotePublicKey() crypto.PubKey {
	return s.remote.libp2pKey
}

func (s *secureSession) SetDeadline(t time.Time) error {
	return s.insecure.SetDeadline(t)
}

func (s *secureSession) SetReadDeadline(t time.Time) error {
	return s.insecure.SetReadDeadline(t)
}

func (s *secureSession) SetWriteDeadline(t time.Time) error {
	return s.insecure.SetWriteDeadline(t)
}

func (s *secureSession) Write(in []byte) (int, error) {
	return s.writeSecure(in)
}

func (s *secureSession) Close() error {
	return s.insecure.Close()
}
